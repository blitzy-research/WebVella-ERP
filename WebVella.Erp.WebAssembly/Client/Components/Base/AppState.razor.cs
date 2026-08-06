using Microsoft.AspNetCore.Components.Routing;
using System.Text.RegularExpressions;

namespace WebVella.Erp.WebAssembly.Components;

public partial class AppState : ComponentBase, IAsyncDisposable
{
	#region << Params and Injects >>
	[Parameter]
	public RenderFragment ChildContent { get; set; }

	[Inject] protected IJSRuntime JSRuntimeSrv { get; set; }

	[Inject] protected NavigationManager Navigator { get; set; }

	[Inject] protected IApiService ApiService { get; set; }

	[Inject] protected IConfigurationService ConfigurationService { get; set; }

	public bool IsDisposed { get; private set; } = false;

	public Guid ComponentId { get; set; } = Guid.NewGuid();

	private DotNetObjectReference<AppState> _objectRef;

	#endregion

	#region << Public props >>

	public Guid SessionId { get; private set; } = Guid.NewGuid();
	public WvUser User { get; private set; } = null;
	#endregion


	#region << Private props >>
	private bool _shouldRender = false;

	private string _errorMessage = "";

	private bool _shouldRerender = true;
	#endregion

	#region << Life cycle >>
	public Task QueueInvokeAsync(Action action)
	{
		return base.InvokeAsync(action);
	}

#pragma warning disable 1998
	public async ValueTask DisposeAsync()
	{
		_objectRef?.Dispose();
		Navigator.LocationChanged -= handleLocationChanged;
		IsDisposed = true;
	}

#pragma warning restore 1998
	protected override async Task OnAfterRenderAsync(bool firstRender)
	{
		if (firstRender)
		{
			_objectRef = DotNetObjectReference.Create((AppState)this);
			//Review finding C-02. This component already models "no logged-in user" as a first-class outcome
			//in the branch just below, but it could never reach it: with no token the call did not return
			//null, it failed - originally by dereferencing a null HttpClient, and now by raising the typed
			//ApiTokenException that replaced that dereference. Either way the render was abandoned by an
			//exception instead of taking the graceful path this component had already written for exactly
			//this condition. Catching only ApiTokenException keeps that distinction intact: an absent or
			//unusable credential falls through to the message below, while any OTHER failure - a transport
			//error, a server fault - still propagates and is not silently reported as "not signed in".
			try
			{
				User = await ApiService.GetCurrentUserAsync();
			}
			catch (ApiTokenException)
			{
				User = null;
			}

			if (User == null)
			{
				_errorMessage = "Няма логнат потребител";
				return;
			}
			Navigator.LocationChanged += handleLocationChanged;
			_shouldRender = true;
			await InvokeAsync(StateHasChanged);
			_shouldRerender = false;
		}
	}

	protected override bool ShouldRender() => _shouldRerender; //this component should never rerender as it is caused by the location change event callback
	#endregion

	#region << Nav >>
	private void handleLocationChanged(object sender, LocationChangedEventArgs e)
	{
		base.InvokeAsync(async () =>
		{
			//await SetSearchBarVisibile(false,this);
			await Task.Delay(2);  // wait for blazor to populate route parameters
			var newLocation = Navigator.Uri;

			_shouldRerender = true;
			await InvokeAsync(StateHasChanged);
			_shouldRerender = false;
		});
	}

	#endregion



}
