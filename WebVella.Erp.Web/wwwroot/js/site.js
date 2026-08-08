"use strict";
var ApiBaseUrl = "/api/v3/en_US";

/*******************************************************************************
FIELDS GENERAL METHODS
*******************************************************************************/

function ProcessConfig(config) {
	if (config !== null && typeof config === 'object') {
		return config;
	}
	else if (config) {
		return JSON.parse(config);
	}
	else {
		return {};
	}
}

function ProcessNewValue(response, fieldName) {
	var newValue = null;
	if (response.object.data && Array.isArray(response.object.data)) {
		newValue = response.object.data[0][fieldName];
	}
	else if (response.object.data) {
		newValue = response.object.data[fieldName];
	}
	else if (response.object) {
		newValue = response.object[fieldName];
	}
	return newValue;
}

/// Go history back for links
////////////////////////////////////////////////////////////
window.goBack = function (e){
    var defaultLocation = "http://www.mysite.com";
    var oldHash = window.location.hash;

    history.back(); // Try to go back

    var newHash = window.location.hash;

    /* If the previous page hasn't been loaded in a given time (in this case
    * 1000ms) the user is redirected to the default location given above.
    * This enables you to redirect the user to another page.
    *
    * However, you should check whether there was a referrer to the current
    * site. This is a good indicator for a previous entry in the history
    * session.
    *
    * Also you should check whether the old location differs only in the hash,
    * e.g. /index.html#top --> /index.html# shouldn't redirect to the default
    * location.
    */

    if(
        newHash === oldHash &&
        (typeof(document.referrer) !== "string" || document.referrer  === "")
    ){
        window.setTimeout(function(){
            // redirect to default location
            window.location.href = defaultLocation;
        },1000); // set timeout in ms
    }
    if(e){
        if(e.preventDefault)
            e.preventDefault();
        if(e.preventPropagation)
            e.preventPropagation();
    }
    return false; // stop event propagation and browser default event
}


$(function(){

	$(".sidebar-switch").on("click", function (ev) {
		ev.preventDefault();
		ev.stopPropagation();
		
		//Should be changed with a ajax call 
		var currentSidebarMode = null;
		if ($("body").hasClass("sidebar-lg")) {
			currentSidebarMode = "lg";
		}
		else if ($("body").hasClass("sidebar-sm")) {
			currentSidebarMode = "sm";
		}

		switch (currentSidebarMode) {
			case "sm":
				$("body").removeClass("sidebar-sm").addClass("sidebar-lg");
				$("#sidebar .sidebar-switch .icon").removeClass("fa-angle-double-right").addClass("fa-angle-double-left");
				break;
			case "lg":
				$("body").removeClass("sidebar-lg").addClass("sidebar-sm");
				$("#sidebar .sidebar-switch .icon").removeClass("fa-angle-double-left").addClass("fa-angle-double-right");
				break;
			default:
				break;
		}

		$.post("/api/v3.0/user/preferences/toggle-sidebar-size", function (data) {
			console.log(data);
		});

	});

	$(".lns-header").on("click", function (ev) {
		ev.preventDefault();
		ev.stopPropagation();
		var collapsable = $(this).closest(".lns").find(".collapse");
		if (collapsable) {
			collapsable.collapse('toggle');
		}
	});

});


//Erp Events for PageComponent communication

const ErpEventPolyfill = function() {
  if (typeof window.ErpEvent === 'function') {
    return;
  }
  
  function ErpEvent(event, params) {
    var evt = document.createEvent('ErpEvent');

    params = params || { bubbles: false, cancelable: false, detail: undefined };
    evt.initErpEvent(event, params.bubbles, params.cancelable, params.detail);
    
    return evt;
  }
  
  ErpEvent.prototype = window.Event.prototype;
  window.ErpEvent = ErpEvent;
};

ErpEventPolyfill();

const TARGET = document;

const ErpEvent = {
  ON: function (eventName, callback) {
    TARGET.addEventListener(eventName, callback);
  },
  OFF: function (eventName, callback) {
    TARGET.removeEventListener(eventName, callback);
  },
  DISPATCH: function (eventName, detail){
      _dispatchEvent(eventName, detail);
  }
};

function _dispatchEvent(eventName, detail) {
  let event = new CustomEvent(eventName, {
    detail
  });

  TARGET.dispatchEvent(event);
}

//ErpEvent.ON('COMPONENT_FULL_NAME',function(event){console.log('event ERP',event)})
// node_id null if targeting all components with this name
//ErpEvent.DISPATCH('COMPONENT_FULL_NAME',{htmlId:null,action:'open',payload:null})
//ErpEvent.DISPATCH('COMPONENT_FULL_NAME','open')


//Fix for modal in modal scroll problem
function FixModalInModalClose() {
	var bodyEl = document.querySelector("body");
	var openModalsCount = $('.modal:visible').length;
	if (!bodyEl.classList.contains("modal-open") && openModalsCount > 0) {
		bodyEl.classList.add("modal-open");
	}
}

//////////////////////////////////////////////////////
/// Helpers 
//////////////////////////////////////////////////////

function isStringNullOrEmptyOrWhiteSpace(str) {
    return (!str || str.length === 0 || /^\s*$/.test(str))
}

function isEmpty(obj) {
    for (var key in obj) {
        if (obj.hasOwnProperty(key))
            return false;
    }
    return true;
}

function checkInt(data) {
    var response = {
        success: true,
        message: "It is integer"
    }
    if (!data) {
        response.message = "Empty value is OK";
        return response;
    }
    if (!isNumeric(data)) {
        response.success = false;
        response.message = "Only integer is accepted";
        return response;
    }

    if (data.toString().indexOf(",") > -1 || data.toString().indexOf(".") > -1) {
        response.success = false;
        response.message = "Only integer is accepted";
        return response;
    }

    if (data === parseInt(data, 10)) {
        return response;
    }
    else {
        response.success = false;
        response.message = "Only integer is accepted";
        return response;
    }

}

function checkDecimal(data) {
    var response = {
        success: true,
        message: "It is decimal"
    }
    if (!data) {
        response.message = "Empty value is OK";
        return response;
    }
    if (data.toString().indexOf(",") > -1) {
        response.success = false;
        response.message = "Comma is not allowed. Use '.' for decimal separator";
        return response;
    }

    if (!isNumeric(data)) {
        response.success = false;
        response.message = "Only decimal is accepted";
        return response;
    }

    return response;
}

function isNumeric(n) {
    return !isNaN(parseFloat(n)) && isFinite(n);
}

function decimalPlaces(num) {
    var match = ('' + num).match(/(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/);
    if (!match) { return 0; }
    return Math.max(
        0,
        // Number of digits right of decimal point.
        (match[1] ? match[1].length : 0)
        // Adjust for scientific notation.
        - (match[2] ? +match[2] : 0));
}

function checkPercent(data) {
    var response = {
        success: true,
        message: "It is decimal"
    }
    if (!data) {
        response.message = "Empty value is OK";
        return response;
    }
    if (data.toString().indexOf(",") > -1) {
        response.success = false;
        response.message = "Comma is not allowed. Use '.' for decimal separator";
        return response;
    }
    if (!isNumeric(data)) {
        response.success = false;
        response.message = "Only decimal is accepted";
        return response;
    }

    if (data > 1) {
        response.success = false;
        response.message = "Only decimal values between 0 and 1 are accepted";
        return response;
    }

    return response;
}

function checkPhone(data) {
    var response = {
        success: true,
        message: "It is decimal"
    }
    if (!phoneUtils.isValidNumber(data)) {
        response.success = false,
            response.message = "Not a valid phone. Should start with + followed by the country code digits";
        return response;
    }


    return response;
}

function checkEmail(data) {
    var response = {
        success: true,
        message: "It is email"
    }
    if (!data) {
        response.message = "Empty value is OK";
        return response;
    }
    var regex = new RegExp("[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?");
    if (!regex.test(_.toLower(data.toString()))) {
        response.success = false;
        response.message = "Invalid email format";
        return response;
    }


    return response;
}

function GetPathTypeIcon(filePath) {
    var fontAwesomeIconName = "fa-file";
    if (filePath.endsWith(".txt")) {
        fontAwesomeIconName = "fa-file-alt";
    }
    else if (filePath.endsWith(".pdf")) {
        fontAwesomeIconName = "fa-file-pdf";
    }
    else if (filePath.endsWith(".doc") || filePath.endsWith(".docx")) {
        fontAwesomeIconName = "fa-file-word";
    }
    else if (filePath.endsWith(".xls") || filePath.endsWith(".xlsx")) {
        fontAwesomeIconName = "fa-file-excel";
    }
    else if (filePath.endsWith(".ppt") || filePath.endsWith(".pptx")) {
        fontAwesomeIconName = "fa-file-powerpoint";
    }
    else if (filePath.endsWith(".gif") || filePath.endsWith(".jpg")
        || filePath.endsWith(".jpeg") || filePath.endsWith(".png")
        || filePath.endsWith(".bmp") || filePath.endsWith(".tif")) {
        fontAwesomeIconName = "fa-file-image";
    }
    else if (filePath.endsWith(".zip") || filePath.endsWith(".zipx")
        || filePath.endsWith(".rar") || filePath.endsWith(".tar")
        || filePath.endsWith(".gz") || filePath.endsWith(".dmg")
        || filePath.endsWith(".iso")) {
        fontAwesomeIconName = "fa-file-archive";
    }
    else if (filePath.endsWith(".wav") || filePath.endsWith(".mp3")
        || filePath.endsWith(".fla") || filePath.endsWith(".flac")
        || filePath.endsWith(".ra") || filePath.endsWith(".rma")
        || filePath.endsWith(".aif") || filePath.endsWith(".aiff")
        || filePath.endsWith(".aa") || filePath.endsWith(".aac")
        || filePath.endsWith(".aax") || filePath.endsWith(".ac3")
        || filePath.endsWith(".au") || filePath.endsWith(".ogg")
        || filePath.endsWith(".avr") || filePath.endsWith(".3ga")
        || filePath.endsWith(".mid") || filePath.endsWith(".midi")
        || filePath.endsWith(".m4a") || filePath.endsWith(".mp4a")
        || filePath.endsWith(".amz") || filePath.endsWith(".mka")
        || filePath.endsWith(".asx") || filePath.endsWith(".pcm")
        || filePath.endsWith(".m3u") || filePath.endsWith(".wma")
        || filePath.endsWith(".xwma")) {
        fontAwesomeIconName = "fa-file-audio";
    }
    else if (filePath.endsWith(".avi") || filePath.endsWith(".mpg")
        || filePath.endsWith(".mp4") || filePath.endsWith(".mkv")
        || filePath.endsWith(".mov") || filePath.endsWith(".wmv")
        || filePath.endsWith(".vp6") || filePath.endsWith(".264")
        || filePath.endsWith(".vid") || filePath.endsWith(".rv")
        || filePath.endsWith(".webm") || filePath.endsWith(".swf")
        || filePath.endsWith(".h264") || filePath.endsWith(".flv")
        || filePath.endsWith(".mk3d") || filePath.endsWith(".gifv")
        || filePath.endsWith(".oggv") || filePath.endsWith(".3gp")
        || filePath.endsWith(".m4v") || filePath.endsWith(".movie")
        || filePath.endsWith(".divx")) {
        fontAwesomeIconName = "fa-file-video";
    }
    else if (filePath.endsWith(".c") || filePath.endsWith(".cpp")
        || filePath.endsWith(".css") || filePath.endsWith(".js")
        || filePath.endsWith(".py") || filePath.endsWith(".git")
        || filePath.endsWith(".cs") || filePath.endsWith(".cshtml")
        || filePath.endsWith(".xml") || filePath.endsWith(".html")
        || filePath.endsWith(".ini") || filePath.endsWith(".config")
        || filePath.endsWith(".json") || filePath.endsWith(".h")) {
        fontAwesomeIconName = "fa-file-code";
    }
    else if (filePath.endsWith(".exe") || filePath.endsWith(".jar")
        || filePath.endsWith(".dll") || filePath.endsWith(".bat")
        || filePath.endsWith(".pl") || filePath.endsWith(".scr")
        || filePath.endsWith(".msi") || filePath.endsWith(".app")
        || filePath.endsWith(".deb") || filePath.endsWith(".apk")
        || filePath.endsWith(".jar") || filePath.endsWith(".vb")
        || filePath.endsWith(".prg") || filePath.endsWith(".sh")) {
        fontAwesomeIconName = "fa-cogs";
    }
    else if (filePath.endsWith(".com") || filePath.endsWith(".net")
        || filePath.endsWith(".org") || filePath.endsWith(".edu")
        || filePath.endsWith(".gov") || filePath.endsWith(".mil")
        || filePath.endsWith("/") || filePath.endsWith(".html")
        || filePath.endsWith(".htm") || filePath.endsWith(".xhtml")
        || filePath.endsWith(".jhtml") || filePath.endsWith(".php")
        || filePath.endsWith(".php3") || filePath.endsWith(".php4")
        || filePath.endsWith(".php5") || filePath.endsWith(".phtml")
        || filePath.endsWith(".asp") || filePath.endsWith(".aspx")
        || filePath.endsWith(".aspx") || filePath.endsWith("?")
        || filePath.endsWith("#")) {
        fontAwesomeIconName = "fa-globe";
    }
    return fontAwesomeIconName;
}

function newGuid() {
	var d = new Date().getTime();
	var uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
		var r = (d + Math.random() * 16) % 16 | 0;
		d = Math.floor(d / 16);
		return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
	});
	return uuid;
};

//Double click causes text to be selected. This clears this text
function clearSelection() {
    if (document.selection && document.selection.empty) {
        document.selection.empty();
    } else if (window.getSelection) {
        var sel = window.getSelection();
        sel.removeAllRanges();
    }
}

var BulgarianDateTimeLocale = {
    weekdays: {
        shorthand: ["Нд", "Пн", "Вт", "Ср", "Чт", "Пт", "Сб"],
        longhand: [
            "Неделя",
            "Понеделник",
            "Вторник",
            "Сряда",
            "Четвъртък",
            "Петък",
            "Събота",
        ],
    },

    months: {
        shorthand: [
            "яну",
            "фев",
            "март",
            "апр",
            "май",
            "юни",
            "юли",
            "авг",
            "сеп",
            "окт",
            "ное",
            "дек",
        ],
        longhand: [
            "Януари",
            "Февруари",
            "Март",
            "Април",
            "Май",
            "Юни",
            "Юли",
            "Август",
            "Септември",
            "Октомври",
            "Ноември",
            "Декември",
        ],
    },
};

function GetFilenameFromUrl(url)
{
   if (url && url !== "")
   {
      return url.split('/').pop().split('#')[0].split('?')[0];
   }
   return "";
}

//////////////////////////////////////////////////////
/// Textarea autogrow => Author: https://github.com/evyros/textarea-autogrow
//////////////////////////////////////////////////////

(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.Autogrow = factory();
  }
})(this, function(){
    return function(textarea, maxLines){
        var self = this;

        if(maxLines === undefined){
            maxLines = 999;
        }

         // Calculates the vertical padding of the element
         // @param textarea
         // @returns {number}
        self.getOffset = function(textarea){
            var style = window.getComputedStyle(textarea, null),
                props = ['paddingTop', 'paddingBottom'],
                offset = 0;

            for(var i=0; i<props.length; i++){
                offset += parseInt(style[props[i]]);
            }
            return offset;
        };

         // Sets textarea height as exact height of content
         // @returns {boolean}
        self.autogrowFn = function(){
            var newHeight = 0, hasGrown = false;
            if((textarea.scrollHeight - offset) > self.maxAllowedHeight){
                textarea.style.overflowY = 'scroll';
                newHeight = self.maxAllowedHeight;
            }
            else {
                textarea.style.overflowY = 'hidden';
                textarea.style.height = 'auto';
                newHeight = textarea.scrollHeight - offset;
                hasGrown = true;
            }
            textarea.style.height = newHeight + 'px';
            return hasGrown;
        };

        var offset = self.getOffset(textarea);
        self.rows = textarea.rows || 1;
        self.lineHeight = (textarea.scrollHeight / self.rows) - (offset / self.rows);
        self.maxAllowedHeight = (self.lineHeight * maxLines) - offset;

        // Call autogrowFn() when textarea's value is changed
        textarea.addEventListener('input', self.autogrowFn);
    };
});


//////////////////////////////////////////////////
// Upload rejection feedback
//////////////////////////////////////////////////
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
		//The image shape's own error indicator, kept as the fixed literal the package uses. The server
		//text goes to the feedback element and the toast below, never into markup.
		//Review finding N20 - the icon carries aria-hidden="true" because it duplicates the word beside it;
		//without it a screen reader announces the font glyph's name as content, which is noise. This matches the
		//widget views changed in the same engagement, which set it on their own decorative icons.
		editWrapper.find(".wrapper-text span").first().html("<i class='fa fa-exclamation-circle go-red' aria-hidden='true'></i> Error").removeClass("d-none");

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
				toastr.error(message, 'Error!', { closeButton: true, tapToDismiss: true });
			}
			if (typeof console !== "undefined" && console.log) {
				console.log(message);
			}
		};
	});
})();


//////////////////////////////////////////////////
// Timer
//////////////////////////////////////////////////
function StartTimer(elementSelector,startTime)
{
    var startTimestamp = moment(startTime);
    setInterval(function() {
        startTimestamp.add(1, 'second');
        document.querySelector(elementSelector).innerHTML = 
            startTimestamp.format('HH:mm:ss');
    }, 1000);
}