// vg-behavior.js — mouse trajectory and keyboard latency analysis.
//
// Detects automated interaction by analyzing the physics of user input.
// Stealth patches fake navigator.webdriver but do NOT synthesize human mouse
// movement or typing cadence. This module measures those signals and fails
// closed when the input profile is robotic.
//
// Obfuscation-safe: no literal close-script or close-style tags in any string.

(function () {
  'use strict';

  // ── Mouse trajectory analysis ────────────────────────────────
  function initMouseMoveTracking() {
    var events = [];
    var tracking = true;
    var startedAt = 0;

    function onMove(e) {
      if (!tracking) return;
      if (!startedAt) startedAt = e.timeStamp;

      events.push({ x: e.clientX, y: e.clientY, t: e.timeStamp });

      if (events.length > 200) events.splice(0, events.length - 200);
    }

    document.addEventListener('mousemove', onMove, { passive: true });

    window.__VG_MOUSE_EVENTS = events;
    window.__VG_MOUSE_TRACKING = function () { return tracking; };
    window.__VG_STOP_MOUSE_TRACKING = function () { tracking = false; };
    window.__VG_START_MOUSE_TRACKING = function () { tracking = true; startedAt = 0; events = []; };

    return events;
  }

  // ── Analyze a trajectory ─────────────────────────────────────
  // Returns { score: 0..1 } where 0 = human, 1 = robotic.
  function analyzeTrajectory(events) {
    if (events.length < 5) return null;

    var segments = [], velocities = [], directions = [];

    for (var i = 1; i < events.length; i++) {
      var dx = events[i].x - events[i - 1].x;
      var dy = events[i].y - events[i - 1].y;
      var dt = events[i].t - events[i - 1].t;
      var dist = Math.sqrt(dx * dx + dy * dy);
      segments.push(dist);
      velocities.push(dt > 0 ? dist / dt : 0);
      directions.push(Math.atan2(dy, dx));
    }

    // 1. Velocity coefficient of variation — humans vary speed, bots don't
    var velMean = 0;
    for (var v = 0; v < velocities.length; v++) velMean += velocities[v];
    velMean /= velocities.length;
    var velVar = 0;
    for (var u = 0; u < velocities.length; u++) {
      var d = velocities[u] - velMean;
      velVar += d * d;
    }
    velVar /= velocities.length;
    var velCV = velMean > 0 ? Math.sqrt(velVar) / velMean : 0;

    // 2. Direction change ratio — humans change direction frequently
    var dirChanges = 0;
    for (var j = 1; j < directions.length; j++) {
      var ad = Math.abs(directions[j] - directions[j - 1]);
      if (ad > Math.PI) ad = 2 * Math.PI - ad;
      if (ad > 0.3) dirChanges++;
    }
    var dirChangeRatio = dirChanges / Math.max(1, directions.length - 1);

    // 3. Path straightness — total path length / straight-line distance
    var totalPath = 0;
    for (var k = 0; k < segments.length; k++) totalPath += segments[k];
    var straightDist = Math.sqrt(
      Math.pow(events[events.length - 1].x - events[0].x, 2) +
      Math.pow(events[events.length - 1].y - events[0].y, 2)
    );
    var straightness = straightDist > 0 ? totalPath / straightDist : 1;

    // 4. Event timing jitter
    var dtValues = [];
    for (var m = 1; m < events.length; m++) {
      var ddt = events[m].t - events[m - 1].t;
      if (ddt > 0 && ddt < 500) dtValues.push(ddt);
    }
    var dtMean = 0;
    for (var n = 0; n < dtValues.length; n++) dtMean += dtValues[n];
    dtMean /= Math.max(1, dtValues.length);
    var dtVar = 0;
    for (var p = 0; p < dtValues.length; p++) {
      var dd = dtValues[p] - dtMean;
      dtVar += dd * dd;
    }
    dtVar /= Math.max(1, dtValues.length);
    var dtCV = dtMean > 0 ? Math.sqrt(dtVar) / dtMean : 0;

    var score = 0;
    if (velCV < 0.15) score += 0.3; else if (velCV < 0.3) score += 0.15;
    if (dirChangeRatio < 0.05) score += 0.25; else if (dirChangeRatio < 0.15) score += 0.12;
    if (straightness < 1.02) score += 0.25; else if (straightness < 1.05) score += 0.12;
    if (dtCV < 0.1) score += 0.2; else if (dtCV < 0.2) score += 0.1;

    return {
      score: Math.min(1, score),
      velCV: velCV,
      dirChangeRatio: dirChangeRatio,
      straightness: straightness,
      dtCV: dtCV,
      eventCount: events.length
    };
  }

  // ── Keyboard latency analysis ─────────────────────────────────
  // Human typing: 80-300ms between keystrokes, high variance.
  // Automation: <30ms, near-zero variance.
  function initKeyboardTracking() {
    var keyTimes = [];

    document.addEventListener('keydown', function (e) {
      keyTimes.push(e.timeStamp);
      if (keyTimes.length > 100) keyTimes.splice(0, keyTimes.length - 100);
    }, true);

    window.__VG_KEY_TIMES = keyTimes;
    return keyTimes;
  }

  function analyzeKeyboardLatency(keyTimes) {
    if (keyTimes.length < 3) return null;

    var intervals = [];
    for (var i = 1; i < keyTimes.length; i++) {
      var d = keyTimes[i] - keyTimes[i - 1];
      if (d > 0 && d < 5000) intervals.push(d);
    }
    if (intervals.length < 2) return null;

    var mean = 0;
    for (var j = 0; j < intervals.length; j++) mean += intervals[j];
    mean /= intervals.length;

    var variance = 0;
    for (var k = 0; k < intervals.length; k++) {
      var d = intervals[k] - mean;
      variance += d * d;
    }
    variance /= intervals.length;
    var std = Math.sqrt(variance);
    var cv = mean > 0 ? std / mean : 0;

    var score = 0;
    if (mean < 30) score += 0.4; else if (mean < 60) score += 0.2;
    if (cv < 0.1) score += 0.4; else if (cv < 0.2) score += 0.2;
    if (intervals.length > 5 && mean < 20) score += 0.2;

    return {
      score: Math.min(1, score),
      meanInterval: mean,
      cv: cv,
      count: intervals.length
    };
  }

  // ── Expose analysis for the slider ────────────────────────────
  // The slider calls these when the drag completes. If the score exceeds
  // the threshold, __VG_KILLPAGE is called.
  window.__VG_ANALYZE_MOUSE = function () {
    if (!window.__VG_MOUSE_EVENTS || window.__VG_MOUSE_EVENTS.length < 5) return null;
    return analyzeTrajectory(window.__VG_MOUSE_EVENTS);
  };

  window.__VG_ANALYZE_KEYBOARD = function () {
    if (!window.__VG_KEY_TIMES || window.__VG_KEY_TIMES.length < 3) return null;
    return analyzeKeyboardLatency(window.__VG_KEY_TIMES);
  };

  // ── Run ───────────────────────────────────────────────────────
  function run() {
    initMouseMoveTracking();
    initKeyboardTracking();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run);
  } else {
    run();
  }
})();

