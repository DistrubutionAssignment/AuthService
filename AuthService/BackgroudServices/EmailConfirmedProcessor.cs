using Azure.Messaging.ServiceBus;
using System.Text.Json;
using AuthService.Models;
using Microsoft.Data.SqlClient;

namespace AuthService.BackgroudServices;

public class EmailConfirmedProcessor : BackgroundService //mycket hjälp från chat gpt här.
{
    private readonly ILogger<EmailConfirmedProcessor> _logger;
    private readonly IConfiguration _configuration;
    private readonly ServiceBusClient _serviceBusClient;
    private ServiceBusProcessor _processor; // ServiceBusProcessor är IDisposable, så vi behöver hantera det korrekt

    public EmailConfirmedProcessor(
        ILogger<EmailConfirmedProcessor> logger,
        IConfiguration configuration,
        ServiceBusClient serviceBusClient)
    {
        _logger = logger;
        _configuration = configuration;
        _serviceBusClient = serviceBusClient;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken) //denna mycket chatgpt o4 highmini
    {
        string queueName = _configuration["ServiceBus:QueueName"]!; // Hämta kö-namnet från keyvault 
        if (string.IsNullOrWhiteSpace(queueName))
        {
            _logger.LogError("ServiceBus:QueueName är inte konfigurerat.");
            return;
        }

        _processor = _serviceBusClient.CreateProcessor(queueName, new ServiceBusProcessorOptions
        {
            AutoCompleteMessages = true,
            MaxConcurrentCalls = 1,
            ReceiveMode = ServiceBusReceiveMode.ReceiveAndDelete
        });

        _processor.ProcessMessageAsync += ProcessMessageHandler;
        _processor.ProcessErrorAsync += ProcessErrorHandler;

        _logger.LogInformation("EmailConfirmedProcessor startar och börjar lyssna på kö: {QueueName}", queueName);
        await _processor.StartProcessingAsync(stoppingToken);

        await Task.Delay(Timeout.Infinite, stoppingToken);
    }

    private async Task ProcessMessageHandler(ProcessMessageEventArgs args)
    {
        try
        {
            string json = args.Message.Body.ToString();
            var payload = JsonSerializer.Deserialize<EmailConfirmedPayload>(json);
            if (payload != null && !string.IsNullOrWhiteSpace(payload.Email))
            {
                string emailLower = payload.Email.ToLowerInvariant();
                await MarkEmailVerifiedInDb(emailLower);
                _logger.LogInformation("EmailVerified: {Email}", emailLower);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Fel vid hantering av EmailConfirmed-meddelande");
        }
    }

    private Task ProcessErrorHandler(ProcessErrorEventArgs args)
    {
        _logger.LogError(args.Exception,
            "Service Bus Fel: Source={ErrorSource}, EntityPath={EntityPath}",
            args.ErrorSource, args.EntityPath);
        return Task.CompletedTask;
    }

    private async Task MarkEmailVerifiedInDb(string email) // Metod för att uppdatera databasen direkt med verifierad e-post
    {
        string connString = _configuration.GetConnectionString("DefaultConnection")!; // Hämta anslutningssträngen från key vault
        await using var conn = new SqlConnection(connString);
        await conn.OpenAsync();

        const string sql = @" 
                UPDATE Users
                SET emailVerified = 1
                WHERE LOWER(Email) = @Email
            ";
        await using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@Email", email);

        int affected = await cmd.ExecuteNonQueryAsync();
        if (affected == 0)
        {
            _logger.LogWarning("Ingen användare hittades med e-post {Email}.", email);
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_processor != null)
        {
            _logger.LogInformation("EmailConfirmedProcessor stoppar processorn...");
            await _processor.StopProcessingAsync(cancellationToken);
            await _processor.DisposeAsync();
            _logger.LogInformation("Service Bus-processor stoppad.");
        }
        await base.StopAsync(cancellationToken);
    }
}
