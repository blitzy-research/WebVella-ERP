//////////////////////////////////////////////////
// Upload rejection feedback
//////////////////////////////////////////////////
//WHY THIS IS ITS OWN, DEFERRED ASSET - and why it must not be folded back into site.js.
//This block used to sit at the end of site.js, and HeadBottomIncludes emits site.js as a SYNCHRONOUS
//<script src> inside <head>. Every byte of it was therefore render-blocking on every page of every host:
//the 350 lines below doubled that file (+18,151 decoded bytes, +6,228 gzipped, +102%) and performance
//verification measured the growth as a constant per-page cost on 13 of 13 pages across all four hosts.
//Serving it separately with the defer attribute takes it off the critical path without changing what it
//does. Nothing here needs to run during parsing: the block only defines functions, records the field id
//of an in-flight upload, and installs one jQuery ajax prefilter - and an upload cannot begin until a user
//has chosen a file, which is necessarily after the document has been parsed.
//Deferring also makes this control strictly MORE reliable than it was. The jQuery guard further down
//returns early when $ is absent, so while this ran as an in-head script it was one include-order change
//away from silently doing nothing at all; a deferred script is guaranteed to run after every synchronous
//<script> in the document, so jQuery is always present by then.
//site.js itself is deliberately NOT deferred, and must not be: it defines page-wide globals - ApiBaseUrl,
//checkInt, checkDecimal, checkEmail, checkPhone, newGuid, GetPathTypeIcon, StartTimer, window.goBack -
//that inline script emitted into the body may call while the document is still parsing.
//
//THREAT ADDRESSED - CWE-754, improper handling of an exceptional condition that carries a security
//decision. POST /fs/upload enforces the extension allow-list, the size cap and the content-type
//consistency check, and refuses a disallowed file with HTTP 400 plus the FSResponse envelope. The
//packaged field widgets that drive that endpoint cannot consume the refusal: their jQuery error
//callbacks read the capitalised ".Message" while the envelope serialises lowercase "message", and the
//very next statement dereferences "response", an identifier those callbacks never declare. The
//resulting ReferenceError aborts each handler at its second statement, so the feedback element, the
//toast and even the console diagnostic never run - the server refuses the file correctly while the
//interface shows a field stuck mid-upload, no reason, and the rejected file still selected and
//submittable. A control whose refusal the user cannot see is a control the user works around, so the
//upload restriction was being reported but not enforced where it had to hold.
//
//Those callbacks live in the WebVella.TagHelpers package and are emitted as inline script, so they
//cannot be edited here: third-party code takes version updates only, and versions 1.8.1 and 1.8.2 were
//both checked and still carry the same two defects, so upgrading is not a remedy either. Reassigning
//the four global functions that build them does not work: two of them create the callback inside a
//change handler bound at field-initialisation time, which has already run by the time any script at the
//end of the document could replace them. jQuery resolves prefilters before it installs a request's
//error callback, so a prefilter is the one hook that reaches a closure created earlier, and it is a
//single hook rather than four reimplementations of vendor logic.
//
//The hook is deliberately narrow twice over. It looks only at POSTs whose path ends exactly at
//"/fs/upload" - never at "/fs/upload-file-multiple" or "/fs/upload-user-file-multiple", whose callbacks
//already read the field correctly - and even then it replaces the callback only when the callback's own
//source proves it carries the defect. A correct handler on the same endpoint is therefore left
//untouched, and this override retires itself the moment the package ships a fixed one. The success path
//is never read or altered, and nothing here relaxes the server-side check: the refusal still comes from
//the server, this only makes it legible and clears the file the server refused.
(function () {
	var UPLOAD_ENDPOINT = "/fs/upload";
	//The field whose upload is in flight. Recorded in the capture phase so it is already set by the time
	//the field's own change handler runs and calls $.ajax, which is when the prefilter executes.
	var activeFieldId = null;

	function rememberFieldId(value) {
		if (value !== null && value !== undefined && String(value).length > 0) {
			activeFieldId = String(value);
		}
	}

	if (document.addEventListener) {
		document.addEventListener("change", function (ev) {
			var target = ev ? ev.target : null;
			if (target && target.id && target.type === "file" && target.id.indexOf("file-") === 0) {
				rememberFieldId(target.id.substring("file-".length));
			}
		}, true);
		//The packaged paste-to-upload path fires no change event; it records its field in this global
		//instead, which is already populated by the time the paste reaches the document.
		document.addEventListener("paste", function () {
			if (typeof FieldFileFormGlobalPasteActiveFieldId !== "undefined") {
				rememberFieldId(FieldFileFormGlobalPasteActiveFieldId);
			}
		}, true);
	}

	function isUploadRequest(options) {
		if (!options || !options.url) {
			return false;
		}
		var verb = String(options.type || options.method || "GET").toUpperCase();
		if (verb !== "POST") {
			return false;
		}
		//Compare the path only, and require it to END at the endpoint, so the longer multi-file upload
		//routes - whose callbacks are already correct - can never be captured by this hook
		var path = String(options.url).split("#")[0].split("?")[0];
		return path === UPLOAD_ENDPOINT || path.slice(-UPLOAD_ENDPOINT.length) === UPLOAD_ENDPOINT;
	}

	//Review finding N18. The source-text test below RECOGNISES the two shipped defects precisely, and that
	//precision is worth keeping - a handler proved defective is replaced outright, which is the behaviour
	//measured against versions 1.8.0, 1.8.1 and 1.8.2. What it must not do is decide the whole question, because
	//any vendor edit - a version bump, a minifier pass, a re-mangled identifier - makes the strings stop
	//matching, and the compensating control would then have failed OPEN with no diagnostic: the server would
	//still refuse the file and the interface would still say nothing. So an UNRECOGNISED handler is no longer
	//left alone silently. It is wrapped instead (see the prefilter below), which tests the vendor's OBSERVABLE
	//behaviour rather than its text: the handler runs, and this file supplies the refusal only if the handler
	//threw or rendered nothing. A future fixed handler therefore retires this override by producing its own
	//feedback, and a future BROKEN one is still covered, neither case depending on the strings above.
	var HANDLER_RECOGNISED = "recognised-defect";
	var HANDLER_UNRECOGNISED = "unrecognised";
	var unrecognisedHandlerReported = false;

	function classifyHandler(handler) {
		if (typeof handler !== "function") {
			return null;
		}
		var source = "";
		try {
			source = Function.prototype.toString.call(handler);
		}
		catch (readError) {
			//A handler whose source cannot be read is not therefore correct - it is unclassified, and is
			//treated as such rather than as safe.
			return HANDLER_UNRECOGNISED;
		}
		//The two defects, in the callback's own source: the undeclared identifier and the capitalised field
		if (source.indexOf("response.message") !== -1 || source.indexOf("responseText).Message") !== -1) {
			return HANDLER_RECOGNISED;
		}
		return HANDLER_UNRECOGNISED;
	}

	//Says so, once per page, when the packaged handler is no longer the one this override was measured against.
	//Silence is what made the brittleness dangerous; a diagnostic makes the drift visible to whoever next
	//upgrades the package, and the wrapper keeps the refusal visible to the user meanwhile.
	function reportUnrecognisedHandler() {
		if (unrecognisedHandlerReported) {
			return;
		}
		unrecognisedHandlerReported = true;
		if (typeof console !== "undefined" && console.log) {
			console.log("WebVella: the upload error handler on " + UPLOAD_ENDPOINT + " is not the version this "
				+ "compensating control was measured against. It is being wrapped rather than replaced, and an "
				+ "upload refusal will still be shown. Re-verify the vendor package's error handling.");
		}
	}

	//True when a refusal is currently visible for the field whose upload just failed. Read AFTER the vendor
	//handler has run, so it answers "did the package report this refusal itself?" rather than "does the package
	//look like it would".
	function hasVisibleRejection() {
		if (activeFieldId === null) {
			return false;
		}
		var fakeInput = $("#fake-" + activeFieldId);
		var editWrapper = $("#edit-" + activeFieldId);
		var fileInput = $("#file-" + activeFieldId);
		var anchor = resolveFieldAnchor(fakeInput, editWrapper, fileInput);
		return anchor.find(".invalid-feedback").length > 0;
	}

	function readServerMessage(xhr, status, p3, p4) {
		var fallback = "Error " + " " + status + " " + p3 + " " + p4;
		if (!xhr || !xhr.responseText || String(xhr.responseText).charAt(0) !== "{") {
			return fallback;
		}
		var parsed = null;
		try {
			parsed = JSON.parse(xhr.responseText);
		}
		catch (parseError) {
			return fallback;
		}
		//The envelope's field is lowercase. This is the whole point of the fix.
		if (parsed && typeof parsed.message === "string" && parsed.message.length > 0) {
			return parsed.message;
		}
		return fallback;
	}

	//The field container both shapes hang their feedback from. Resolved from whichever of the three
	//anchors this widget shape actually renders, because the two shapes do not agree on all of them: the
	//image shape names its wrapper-text element "fake-<name>-<id>" rather than "fake-<id>", so the
	//"#fake-" lookup finds nothing there while "#file-" and "#edit-" both resolve. Deriving the container
	//from the first anchor that exists is what lets one routine serve both shapes.
	function resolveFieldAnchor(fakeInput, editWrapper, fileInput) {
		var container = fileInput.closest(".wv-field");
		if (container.length === 0) {
			container = fakeInput.closest(".wv-field");
		}
		if (container.length === 0) {
			container = editWrapper.closest(".wv-field");
		}
		return container.length > 0 ? container : editWrapper;
	}

	//Retracts the refusal once an upload for the same field is ACCEPTED. Making the refusal visible - the
	//whole point of the override above - introduced a second way to misinform the user: the packaged
	//success callback renders the accepted file but never clears a previous refusal, so a user refused
	//once and then uploading an allowed file would see the obsolete refusal sitting under the new
	//thumbnail, reporting a failure that did not happen. A control that reports the wrong outcome is as
	//unusable as one that reports none, in the opposite direction. Only what renderRejection added is
	//removed, and only for the field whose upload just completed.
	function clearRejection() {
		if (activeFieldId === null) {
			return;
		}
		var fakeInput = $("#fake-" + activeFieldId);
		var editWrapper = $("#edit-" + activeFieldId);
		var fileInput = $("#file-" + activeFieldId);

		fakeInput.removeClass("is-invalid");
		//Review finding N20 - the assistive-technology state is retracted with the visual one. Leaving
		//aria-invalid="true" behind would keep announcing a refusal that has been superseded by an accepted
		//upload, which is the same "reports the wrong outcome" failure the visual cleanup exists to prevent.
		fakeInput.removeAttr("aria-invalid").removeAttr("aria-describedby");
		fileInput.removeAttr("aria-invalid").removeAttr("aria-describedby");
		resolveFieldAnchor(fakeInput, editWrapper, fileInput).find(".invalid-feedback").remove();
		//Review finding F-130. The in-tile indicator is retracted with everything else, and this is not merely
		//symmetry for the title and class added beside it in renderRejection: without it the red error glyph
		//stayed on the tile after a LATER upload was accepted, so the thumbnail of a successfully stored image
		//still carried a refusal marker. That is the same "reports the wrong outcome" failure this whole routine
		//exists to prevent, in the one channel that had been left out of it. Restored to the exact shape the
		//package ships pristine - an empty span carrying only d-none - so nothing of this override survives a
		//success.
		editWrapper.find(".wrapper-text span").first()
			.removeAttr("title")
			.removeClass("text-nowrap")
			.empty()
			.addClass("d-none");
	}

	//Renders the refusal into whichever of the two field shapes is on the page. Every anchor the packaged
	//callbacks touch sits inside the field's .wv-field container, and both shapes derive every one of
	//their selectors from the same field id, so one routine covers all of them without branching per
	//widget. The message is applied with .text(), never concatenated into markup.
	function renderRejection(message) {
		if (activeFieldId === null) {
			return;
		}
		var fakeInput = $("#fake-" + activeFieldId);
		var editWrapper = $("#edit-" + activeFieldId);
		var fileInput = $("#file-" + activeFieldId);

		//Leave the field at rest rather than frozen at the progress it reached
		$("#fake-" + activeFieldId + " .form-control-progress").first().attr("style", "display:none;width:0%").text("");
		$("#fake-" + activeFieldId + " a").show();
		fakeInput.addClass("is-invalid");
		//The image shape's own error indicator. The server text goes to the feedback element and the toast
		//below, never into markup.
		//Review finding N20 - the icon carries aria-hidden="true" because it duplicates the message beside it;
		//without it a screen reader announces the font glyph's name as content, which is noise. This matches the
		//widget views changed in the same engagement, which set it on their own decorative icons.
		//Review finding F-130 - the word "Error" used to follow this icon and was UNREADABLE, so a refusal the
		//user could not fully read was being reported by the one channel meant to be glanceable. The cause is
		//geometry, and it was measured rather than guessed: the tile is the clipper, carrying an inline
		//height:80px with overflow:hidden, so its content box ends at a hard boundary. Inside it .wrapper-text is
		//absolutely positioned, only 80px wide and already holds the "select" button, so icon + space + "Error"
		//could not fit on the button's line; the span wrapped to a second line and its bottom edge landed 6px
		//past the tile's, leaving the top half of the glyphs showing and the rest cut off. Because that height is
		//a FIXED 80px at every viewport width - confirmed identical at 1440 and 1600 - the clipping was
		//deterministic rather than a narrow-screen edge case, and no amount of container growth below the tile
		//could have helped.
		//The word is therefore dropped rather than repositioned. It was pure redundancy: the same refusal is
		//already stated in full, in words, in the .invalid-feedback element immediately below the tile - which is
		//the assertive live region added for N20 - and again in the toast. What is left is a single 14px glyph
		//that cannot wrap and so cannot be clipped, which is the smallest change that closes the finding
		//(Minimal Change guideline 7); the alternatives - overriding the vendor's fixed height, or absolutely
		//positioning a badge and hoping the text fits 80px at every font size - both risk re-introducing the
		//clip. title carries the word for a pointer user, text-nowrap is Bootstrap's own class rather than an
		//inline style so it adds no report-only Content-Security-Policy violation, and the accessible name is
		//unaffected because it never came from this glyph.
		editWrapper.find(".wrapper-text span").first()
			.attr("title", "Error")
			.addClass("text-nowrap")
			.html("<i class='fa fa-exclamation-circle go-red' aria-hidden='true'></i>")
			.removeClass("d-none");

		//Drop the refused file so it cannot be carried into a save. Without this the interface still
		//holds the file the server just rejected.
		fileInput.val("");

		var anchor = resolveFieldAnchor(fakeInput, editWrapper, fileInput);
		//Replace any feedback left by an earlier rejection instead of stacking another one
		anchor.find(".invalid-feedback").remove();
		//Review finding N20 - a refusal a screen-reader user cannot perceive is the same defect, for that user,
		//that the invisible refusal above was for a sighted one: the control appears to have accepted the file.
		//role="alert" makes the message an assertive live region so it is announced when it is inserted, and
		//aria-live="polite" is stated with it so a user agent that does not map the role still announces it.
		//The id is derived from the field id, so aria-describedby below binds this exact message to this exact
		//field even when several file fields sit on one page.
		var feedbackId = "upload-rejection-" + activeFieldId;
		var feedback = $("<div class='invalid-feedback'></div>")
			.attr("id", feedbackId)
			.attr("role", "alert")
			.attr("aria-live", "polite")
			.text(message);
		//The refusal is announced AND the field is marked invalid and pointed at its reason, so a user arriving
		//at the control afterwards - rather than at the moment of the announcement - still learns both facts.
		//Both anchors are marked because the two widget shapes focus different elements.
		fakeInput.attr("aria-invalid", "true").attr("aria-describedby", feedbackId);
		fileInput.attr("aria-invalid", "true").attr("aria-describedby", feedbackId);
		var inputGroup = anchor.find(".input-group").first();
		if (inputGroup.length > 0) {
			inputGroup.after(feedback);
		}
		else if (editWrapper.length > 0) {
			editWrapper.after(feedback);
		}
		else {
			anchor.append(feedback);
		}
		feedback.show();
	}

	if (typeof $ === "undefined" || !$ || typeof $.ajaxPrefilter !== "function") {
		return;
	}

	$.ajaxPrefilter(function (options, originalOptions, jqXHR) {
		if (!isUploadRequest(options)) {
			return;
		}
		var handlerKind = classifyHandler(options.error);
		if (handlerKind === null) {
			//No error handler at all: the refusal has nowhere to surface, so this file supplies one. Previously
			//this case was indistinguishable from a correct handler and produced silence.
			handlerKind = HANDLER_UNRECOGNISED;
		}
		if (handlerKind === HANDLER_UNRECOGNISED) {
			reportUnrecognisedHandler();
		}
		var packagedErrorHandler = typeof options.error === "function" ? options.error : null;
		//The stale-refusal cleanup is registered on the jqXHR rather than by wrapping options.success, and
		//the distinction matters twice. jQuery installs a request's own success callback AFTER prefilters
		//have run, so a handler added here is registered first and clears the obsolete message before the
		//packaged callback renders the accepted value. And the packaged callback is left exactly as the
		//package shipped it - including the case where jQuery was handed an ARRAY of success handlers,
		//which a wrapper testing for a single function would have silently discarded. Failure is contained
		//so a surprise in the cleanup can never suppress the upload the user just completed.
		if (jqXHR && typeof jqXHR.done === "function") {
			jqXHR.done(function () {
				try {
					clearRejection();
				}
				catch (clearError) {
					if (typeof console !== "undefined" && console.log) {
						console.log(clearError);
					}
				}
			});
		}
		options.error = function (xhr, status, p3, p4) {
			var message = readServerMessage(xhr, status, p3, p4);
			//An unrecognised handler is RUN FIRST and its failure contained, so a package that has since been
			//fixed keeps reporting its own refusal in its own words and this file adds nothing. A recognised
			//defect is not run at all, which is the measured behaviour: its second statement raises a
			//ReferenceError, so running it would buy nothing and cost an avoidable exception.
			var packagedHandlerReported = false;
			if (handlerKind === HANDLER_UNRECOGNISED && packagedErrorHandler !== null) {
				//Any refusal left by an EARLIER attempt is retracted before the packaged handler runs, and that
				//ordering is load-bearing rather than tidiness. The probe below asks "is a refusal visible now?",
				//which without this retraction answers yes for a message this file rendered on a previous
				//attempt - so a second failure would credit the packaged handler with output it never produced,
				//skip the re-render, and leave the EARLIER message on screen while the live region is never
				//re-inserted. That would report the wrong reason to a sighted user and nothing at all to a
				//screen-reader user, which is the defect this whole block exists to prevent.
				try {
					clearRejection();
				}
				catch (clearBeforeError) {
					if (typeof console !== "undefined" && console.log) {
						console.log(clearBeforeError);
					}
				}
				try {
					packagedErrorHandler.apply(this, arguments);
					packagedHandlerReported = hasVisibleRejection();
				}
				catch (packagedError) {
					if (typeof console !== "undefined" && console.log) {
						console.log(packagedError);
					}
				}
			}
			//A package that reported the refusal itself is left to speak for itself on every channel: adding a
			//second feedback element and a second toast to a working handler would be change without benefit,
			//and it is what lets this override retire itself when the package is fixed.
			if (packagedHandlerReported) {
				return;
			}
			//Each channel is isolated so a surprise in one cannot suppress the others - the failure mode
			//this replaces was precisely one statement stopping every report that followed it
			try {
				renderRejection(message);
			}
			catch (renderError) {
				if (typeof console !== "undefined" && console.log) {
					console.log(renderError);
				}
			}
			if (typeof toastr !== "undefined" && toastr && typeof toastr.error === "function") {
				//Review findings F-131 and F-132. The position and the lifetime are now stated outright, because
				//this call supplied neither, and both omissions had consequences that were measured on the
				//running application rather than reasoned about.
				//POSITION (F-131). Inheriting toastr's default put the notification at toast-top-right, whose
				//stylesheet rule is "top:12px; right:12px". On a 1600px viewport that resolves to the rectangle
				//x1288-1588, y12-72, and the page header's primary actions sit at x1423-1518 (Save User) and
				//x1526-1585 (Cancel), y54-83. The notification therefore covered 100% of the width and 62% of
				//the height of BOTH buttons, and elementFromPoint over each of them returned the toast - so at
				//the exact moment the user has to react to a refusal, the two controls they would react WITH
				//were obscured, and the longer the server's message the further down it grew. toast-top-center
				//clears the header's action area entirely, and it is not an invented value: it is the position
				//this product's own ScreenMessage component already uses for every other notification it
				//raises, so the refusal now appears where users are used to looking.
				//LIFETIME (F-132). With no timeOut the duration was whatever toastr.options happened to hold at
				//the moment of the call - an empty object today, so the library's own 5000ms applied, but that
				//object is global and mutable, and any component or test harness that assigns to it silently
				//reassigns the lifetime of THIS security refusal too. A control whose visibility depends on a
				//mutable global is not a control. 7000/7000 states it outright and matches the value
				//ScreenMessage uses for its own error notifications, so the refusal is no longer the
				//shortest-lived message in the product by accident.
				toastr.error(message, 'Error!', {
					positionClass: "toast-top-center",
					newestOnTop: false,
					timeOut: 7000,
					extendedTimeOut: 7000,
					closeButton: true,
					tapToDismiss: true
				});
			}
			if (typeof console !== "undefined" && console.log) {
				console.log(message);
			}
		};
	});
})();
