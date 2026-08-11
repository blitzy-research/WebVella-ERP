"use strict";
/*
	P6-03 (Visual / Data-driven UI) - the project dashboard's doughnut widgets rendered five coloured
	segments that carried no identification of any kind: `labels: []`, `datasets[0].label: null`,
	`options.legend.display: false` and `options.tooltips.enabled: false`, with zero legend DOM nodes and
	no `title` on the canvas. Hovering an arc registered the hit (`tooltip._active === 1`) but painted
	nothing (`_model.opacity === 0`), so a reader could see a proportion and never learn what it measured.

	WHY THIS IS A SEPARATE FILE RATHER THAN A VIEW CHANGE. The three widgets render their charts through
	`<wv-chart>`, a tag helper from the third-party WebVella.TagHelpers package. That helper builds the
	whole Chart.js configuration itself and writes `"tooltips":{"enabled":false}` into it unconditionally;
	its public surface is only `type`, `datasets`, `labels`, `show-legend`, `id`, `width` and `height`, so
	there is no attribute through which a view can turn tooltips on. The delivery contract permits version
	updates to vendor packages but not edits to them, so the option has to be corrected from the client
	after the helper has emitted its configuration and before Chart.js reads it.

	WHY A PLUGIN, AND WHY `beforeInit`. Chart.js v2.8.0's `Chart.Controller.initialize()` runs
	`plugins.notify(this, "beforeInit")` as its first statement and only calls `initToolTip()` four
	statements later, so a `beforeInit` hook is the last point at which `options.tooltips` can still be
	changed and the first at which the chart's own configuration is available. That ordering was read out
	of the shipped bundle rather than assumed. The alternatives were both worse: `Chart.defaults` cannot
	work, because the per-chart `enabled: false` the helper emits overrides any default; and reaching into
	`Chart.instances` after `window.load` would repaint every chart on the page for a result this achieves
	before the first paint.

	WHY IT IS SCOPED, NOT GLOBAL. The hook only touches doughnut and pie charts that actually carry
	labels. A chart with `labels: []` is left exactly as it was, because a tooltip with no text to show is
	a worse outcome than no tooltip - so switching this file on cannot change any chart that has not also
	been given the labels to describe itself.

	WHY THE TOOLTIP IS RESTYLED. These canvases are 100x100 CSS px and Chart.js v2 paints tooltips onto
	the canvas, so anything wider than the canvas is clipped. Dropping the colour swatch (the arc under
	the cursor already carries the colour) and tightening the font and padding keeps the box inside the
	canvas; the widths were measured on the live widgets rather than estimated.

	Loaded with a plain <script src> from the widgets' own views, which is the pattern four other
	components in this plugin already use, and which keeps the mandated `script-src 'self'` policy
	satisfied - no inline script is added anywhere by this fix.
*/
(function (window) {

	var Chart = window.Chart;

	//The helper emits Chart.bundle.min.js immediately before the canvas, so Chart is defined by the time
	//this file is parsed. Guard anyway: if the bundle ever fails to load, a chart without a tooltip is
	//the correct degradation and a thrown error on every dashboard is not.
	if (!Chart || !Chart.plugins || typeof Chart.plugins.register !== "function") {
		return;
	}

	//Each of the three widgets includes this file, so on a dashboard carrying more than one chart the
	//same source is parsed more than once. Registering the same behaviour repeatedly would be harmless
	//but is still wrong, so the registration is made exactly once per document.
	if (window.wvChartSegmentTooltipsRegistered === true) {
		return;
	}
	window.wvChartSegmentTooltipsRegistered = true;

	Chart.plugins.register({

		id: "wvChartSegmentTooltips",

		beforeInit: function (chart) {

			if (!chart || !chart.config) {
				return;
			}

			var type = chart.config.type;
			if (type !== "doughnut" && type !== "pie") {
				return;
			}

			//No labels means nothing to say. Leave the chart untouched rather than enabling an empty box.
			var data = chart.config.data;
			if (!data || !data.labels || data.labels.length === 0) {
				return;
			}

			//`chart.options` is assigned from `chart.config.options` during construction, but write through
			//both references so this does not depend on them still being the same object.
			var targets = [chart.config.options];
			if (chart.options && chart.options !== chart.config.options) {
				targets.push(chart.options);
			}

			for (var i = 0; i < targets.length; i++) {

				var options = targets[i];
				if (!options) {
					continue;
				}

				if (!options.tooltips) {
					options.tooltips = {};
				}

				options.tooltips.enabled = true;

				//Sized to stay inside a 100x100 canvas - see the note above.
				options.tooltips.displayColors = false;
				options.tooltips.titleFontSize = 10;
				options.tooltips.bodyFontSize = 10;
				options.tooltips.xPadding = 4;
				options.tooltips.yPadding = 3;
				options.tooltips.caretSize = 4;
				options.tooltips.cornerRadius = 2;
			}
		}
	});

})(window);
