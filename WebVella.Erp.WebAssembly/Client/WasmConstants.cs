namespace WebVella.Erp.WebAssembly;

public class WasmConstants
{
    public static CultureInfo Culture = new CultureInfo("bg-BG");
    public static CultureInfo NumberCulture = new CultureInfo("en-US");
    public const string DateFormat = "dd.MM.yyyy";
    public const string HourFormat = "HH:mm";
    public const string DateFormatUrl = "yyyy-MM-dd";
    public const string YearMonthFormatUrl = "yyyy-MM";
    public const string DateHourFormat = "dd MMM yyyy HH:mm";
    public const string DateTimeFormat = "dd MMM yyyy HH:mm:ss";
    public const string NumberFormat = "G0";

    //Query params
    public const string ReturnUrlQuery = "returnUrl";

    /// <summary>
    /// Route root of the platform's JWT authentication endpoints, RELATIVE to the configured API base.
    /// </summary>
    /// <remarks>
    /// Review finding C-01. The HttpClient's BaseAddress already ends in "api/", so every route composed
    /// against it must NOT repeat that segment. Two services compose these endpoints and they had drifted
    /// apart: one omitted the segment and worked, the other included it and produced "/api/api/v3/..." -
    /// a 404 on the token-refresh path, which silently turned every expiring session into a forced logout.
    /// Defining the root once removes the possibility of that divergence recurring rather than correcting
    /// one of its two spellings.
    /// </remarks>
    public const string ApiAuthRoot = "v3/en_US/auth/jwt/";
}
