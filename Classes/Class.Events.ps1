<#
    .SYNOPSIS
        Logs custom events to a Windows Event Log with predefined categories and severities,
        along with flexible options for customization.

    .DESCRIPTION
        The EventLogging module provides the ability to log predefined or custom events to a Windows Event Log.
        This module includes various event categories and severity levels to match common use cases such as User Activity,
        System Health, Error Handling, and more.
        The logging mechanism is flexible, allowing users to log events with predefined settings or custom ones.
        It also supports additional logging in JSON format to a local file.

    .PARAMETER EventInfo
        Predefined event metadata from the EventIDs class (for predefined events).

    .PARAMETER CustomEventId
        The custom event ID to use when logging a custom event.

    .PARAMETER EventName
        Name of the custom event when using the Custom parameter set.

    .PARAMETER EventCategory
        The category of the event, either predefined or custom.

    .PARAMETER Message
        The message to log in the event. This will be the detailed description shown in the event log entry.

    .PARAMETER Severity
        The severity level of the event (Information, Warning, Error, etc.), predefined or custom.

    .PARAMETER LogAsJson
        Switch to log the event in JSON format to a local file (for centralized logging or integration).

    .PARAMETER MaximumKilobytes
        Optional. The maximum size (in KB) of the event log before it overwrites older logs. Default is 16384 KB (16 MB).

    .PARAMETER RetentionDays
        Optional. The number of days to retain log entries. Default is 30 days.

    .EXAMPLE
        # Predefined event log example:
        Write-CustomLog -EventInfo ([EventIDs]::UserLogin) -Message "User logged in successfully" -Verbose

    .EXAMPLE
        # Custom event log example:
        Write-CustomLog -CustomEventId ([EventID]::LowDiskSpace) -EventName "LowDiskSpace" `
        -EventCategory SystemHealth -Message "Low disk space on C: drive" `
        -CustomSeverity Warning -WhatIf

    .EXAMPLE
        # Log event to JSON file:
        Write-CustomLog -CustomEventId ([EventID]::AuthenticationFailed) `
        -EventName "AuthFailure" -EventCategory Security `
        -Message "Authentication failure for user JohnDoe" `
        -CustomSeverity Error -LogAsJson

    .NOTES
        This module is designed for use in environments where detailed event logging is required for auditing and monitoring.
        It supports event log retention and overwriting old entries based on user-defined limits.
        Sensitive information is masked before logging to prevent leaks of confidential data.
#>

Add-Type -Language CSharp -TypeDefinition @'

using System;
using System.Diagnostics;






// Enumeration for defining the category of events (System, Application, Security).
/// <summary>
/// EventCategory enumeration to classify the event (System, Application, Security).
/// </summary>
public enum EventCategory
{
    None = 0,
    General = 1,
    Security = 2,
    SystemHealth = 3,
    Performance = 4,
    UserActivity = 5,
    DataManagement = 6,
    Initialization = 7,
    Execution = 8,
    Cleanup = 9,
    ErrorHandling = 10
}





// Enumeration for defining the Event ID, representing different types of events (Info, Warning, Error).
/// <summary>
/// EventID enumeration to define the type of event (Info, Warning, Error). Define Event Severity (maps to EventLogEntryType)
/// </summary>
public enum EventSeverity
{
    None = 0,
    Information = 1,
    Warning = 2,
    Error = 3,
    SuccessAudit = 4,
    FailureAudit = 5
}






// Enumeration for defining the Event ID, representing different types of events (Info, Warning, Error).
/// <summary>
/// EventID enumeration to define the type of events.
/// </summary>
public enum EventID
{
    // Informational events (1000-9999)
    ////////////////////////////////////////////////////////////////////////////////
    UserLogin = 1000,
    ConfigurationChanged = 1001,
    TaskStarted = 1002,
    TaskCompleted = 1003,

    FunctionCalled = 2100,
    GetGroupMembership = 2200,
    SetGroupMembership = 2300,





    // Warning events (10000-19999)
    ////////////////////////////////////////////////////////////////////////////////
    LowDiskSpace = 10000,
    SlowPerformance = 10001,

    InvalidSID = 10005,





    // Error events (20000-29999)
    ////////////////////////////////////////////////////////////////////////////////
    DatabaseConnectionFailed = 20000,
    AuthenticationFailed = 20001,

    FailedGetGroupMembership = 20200,
    FailedSetGroupMembership = 20300,





    // Critical events (30000-39999)
    ////////////////////////////////////////////////////////////////////////////////
    ServiceCrashed = 30000,
    DataCorruption = 30001





    // Other Not-Defined events (40000-65535)
    ////////////////////////////////////////////////////////////////////////////////

} //end Enum






// The EventIdInfo class contains detailed information about an event, including ID, name, description, category, and severity.
/// <summary>
/// EventIdInfo class to store event metadata such as ID, name, description, category, and severity.
/// </summary>
public class EventIDInfo
{
    /// <summary>
    /// Gets the ID of the event.
    /// </summary>
    public EventID ID { get; private set; }

    /// <summary>
    /// Gets the name of the event.
    /// </summary>
    public string Name { get; private set; }

    /// <summary>
    /// Gets the description of the event.
    /// </summary>
    public string Description { get; private set; }

    /// <summary>
    /// Gets the category of the event.
    /// </summary>
    public EventCategory Category { get; private set; }

    /// <summary>
    /// Gets the default severity of the event.
    /// </summary>
    public EventSeverity DefaultSeverity { get; private set; }


    /// <summary>
    /// Initializes a new instance of the EventIdInfo class with the specified parameters.
    /// </summary>
    /// <param name="id">The ID of the event, defined by the EventID enumeration.</param>
    /// <param name="name">The name of the event.</param>
    /// <param name="description">A brief description of the event.</param>
    /// <param name="category">The category of the event, defined by the EventCategory enumeration.</param>
    /// <param name="severity">The default severity of the event, defined by the EventSeverity enumeration.</param>
    public EventIDInfo(EventID id, string name, string description, EventCategory category, EventSeverity severity)
    {
        this.ID = id;
        this.Name = name;
        this.Description = description;
        this.Category = category;
        this.DefaultSeverity = severity;
    }
} //end Class






/// <summary>
/// Define all Event IDs
/// </summary>
public static class EventIDs
{

    // Information
    ////////////////////////////////////////////////////////////////////////////////

    public static readonly EventIDInfo UserLogin = new EventIDInfo(
        EventID.UserLogin,
        "UserLogin",
        "User logged into the system",
        EventCategory.UserActivity,
        EventSeverity.Information
    );

    public static readonly EventIDInfo ConfigurationChanged = new EventIDInfo(
        EventID.ConfigurationChanged,
        "ConfigurationChanged",
        "System configuration was modified",
        EventCategory.General,
        EventSeverity.Information
    );

    public static readonly EventIDInfo TaskCompleted = new EventIDInfo(
        EventID.TaskCompleted,
        "TaskCompleted",
        "A scheduled task completed successfully",
        EventCategory.Execution,
        EventSeverity.Information
    );

    public static readonly EventIDInfo GetGroupMembership = new EventIDInfo(
        EventID.GetGroupMembership,
        "Get Group Membership",
        "Getting group membership successfully.",
        EventCategory.UserActivity,
        EventSeverity.Information
    );

    public static readonly EventIDInfo SetGroupMembership = new EventIDInfo(
        EventID.SetGroupMembership,
        "Set Group Membership",
        "Setting group membership successfully.",
        EventCategory.UserActivity,
        EventSeverity.Information
    );






    // Warning
    ////////////////////////////////////////////////////////////////////////////////

    public static readonly EventIDInfo LowDiskSpace = new EventIDInfo(
        EventID.LowDiskSpace,
        "LowDiskSpace",
        "Available disk space is running low",
        EventCategory.SystemHealth,
        EventSeverity.Warning
    );

    public static readonly EventIDInfo SlowPerformance = new EventIDInfo(
        EventID.SlowPerformance,
        "SlowPerformance",
        "System performance is degraded",
        EventCategory.Performance,
        EventSeverity.Warning
    );

    public static readonly EventIDInfo InvalidSID = new EventIDInfo(
        EventID.InvalidSID,
        "InvalidSID",
        "The SID provided is not valid.",
        EventCategory.Security,
        EventSeverity.Warning
    );






    // Error
    ////////////////////////////////////////////////////////////////////////////////

    public static readonly EventIDInfo DatabaseConnectionFailed = new EventIDInfo(
        EventID.DatabaseConnectionFailed,
        "DatabaseConnectionFailed",
        "Failed to connect to the database",
        EventCategory.DataManagement,
        EventSeverity.Error
    );

    public static readonly EventIDInfo AuthenticationFailed = new EventIDInfo(
        EventID.AuthenticationFailed,
        "AuthenticationFailed",
        "User authentication failed",
        EventCategory.Security,
        EventSeverity.Error
    );

    public static readonly EventIDInfo ServiceCrashed = new EventIDInfo(
        EventID.ServiceCrashed,
        "ServiceCrashed",
        "A critical service has stopped unexpectedly",
        EventCategory.ErrorHandling,
        EventSeverity.Error
    );

    public static readonly EventIDInfo DataCorruption = new EventIDInfo(
        EventID.DataCorruption,
        "DataCorruption",
        "Data integrity compromised",
        EventCategory.DataManagement,
        EventSeverity.Error
    );

    public static readonly EventIDInfo FailedGetGroupMembership = new EventIDInfo(
        EventID.FailedGetGroupMembership,
        "Failed to get Group Membership",
        "Error while getting group membership",
        EventCategory.UserActivity,
        EventSeverity.Error
    );

    public static readonly EventIDInfo FailedSetGroupMembership = new EventIDInfo(
        EventID.FailedSetGroupMembership,
        "Failed to set Group Membership",
        "Error while setting group membership",
        EventCategory.UserActivity,
        EventSeverity.Error
    );

} //end Class


'@
