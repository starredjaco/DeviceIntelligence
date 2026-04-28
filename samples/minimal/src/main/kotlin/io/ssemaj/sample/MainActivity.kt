package io.ssemaj.sample

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.Gravity
import android.view.ViewGroup
import android.view.Window
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import io.ssemaj.deviceintelligence.DeviceIntelligence
import io.ssemaj.deviceintelligence.Severity
import io.ssemaj.deviceintelligence.SelfProtectListener
import io.ssemaj.deviceintelligence.TelemetryReport
import io.ssemaj.deviceintelligence.testing.SelfProtectTestRig
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicInteger

/**
 * Telemetry viewer for the DeviceIntelligence sample.
 *
 * DeviceIntelligence is a telemetry layer — it does not block, lock, or crash. The
 * sample reflects that: there is no "verdict". Instead the screen
 * shows the latest [TelemetryReport] as both a summary chip row and
 * its canonical JSON, and the user can:
 *
 *  - **Re-collect**: re-run every detector and re-render. Useful for
 *    manually re-checking after the user changes app state (e.g.
 *    after triggering a test tamper).
 *  - **Copy JSON**: copy the full JSON to the clipboard, exactly as
 *    a backend would receive it.
 *  - **Tamper text now**: ask [SelfProtectTestRig] to flip one byte
 *    of `libdicore.so` `.text`, which the F11 watchdog will pick
 *    up; the next collect will surface a `native_text_drift` finding.
 *
 * The F11 watchdog is started in [onCreate] and runs for the lifetime
 * of the activity; its real-time [SelfProtectListener] callback just
 * appends a line to the on-screen event log so the demo stays
 * self-evident.
 */
class MainActivity : Activity() {

    private val mainHandler = Handler(Looper.getMainLooper())
    private val tamperEvents = AtomicInteger(0)

    private lateinit var heroContainer: LinearLayout
    private lateinit var summaryChips: LinearLayout
    private lateinit var actionsRow: LinearLayout
    private lateinit var jsonView: TextView
    private lateinit var eventLogView: TextView

    @Volatile
    private var lastReport: TelemetryReport? = null
    @Volatile
    private var lastJson: String = ""

    private val eventLog = ArrayDeque<String>()
    private val eventLogLimit = 12
    private val timeFmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runCatching { requestWindowFeature(Window.FEATURE_NO_TITLE) }
        actionBar?.hide()

        setContentView(buildScaffold())
        appendEvent("activity created")

        // Run once before paint so the first frame already has data.
        runCollect(initial = true)

        // Start the F11 watchdog. The accumulated state surfaces in
        // every subsequent collect via the F11.self_protect detector,
        // but the real-time listener still fires the moment any drift
        // happens — wired here just to make the demo expressive.
        DeviceIntelligence.startSelfProtect(
            intervalMs = 500L,
            listener = SelfProtectListener { drifted ->
                tamperEvents.incrementAndGet()
                mainHandler.post {
                    appendEvent("F11 listener fired: $drifted region(s) drifted")
                }
            },
        )
    }

    override fun onDestroy() {
        super.onDestroy()
        mainHandler.removeCallbacksAndMessages(null)
        DeviceIntelligence.stopSelfProtect()
    }

    // ---- scaffold ----------------------------------------------------------

    private fun buildScaffold(): ScrollView {
        val pad = Ui.dp(this, 16)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            setBackgroundColor(Ui.Colors.PAGE_BG)
        }

        heroContainer = Ui.heroBanner(this, Ui.Tone.NEUTRAL).also { root.addView(it) }

        val summaryCard = Ui.card(this).also { root.addView(it) }
        summaryCard.addView(Ui.titleRow(this, "Latest collect"))
        summaryCard.addView(
            Ui.subtitle(
                this,
                "Counts roll up every Finding from every Detector.",
            ),
        )
        summaryChips = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = Ui.dp(this@MainActivity, 8) }
        }
        summaryCard.addView(summaryChips)

        val actionsCard = Ui.card(this).also { root.addView(it) }
        actionsCard.addView(Ui.titleRow(this, "Actions"))
        actionsCard.addView(
            Ui.subtitle(
                this,
                "Recollect re-runs every detector. Tamper flips one byte of libdicore .text — the next collect should surface a 'native_text_drift' finding.",
            ),
        )
        actionsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = Ui.dp(this@MainActivity, 8) }
        }
        actionsRow.addView(makeButton("Re-collect") { runCollect(initial = false) })
        actionsRow.addView(makeButton("Copy JSON") { copyJsonToClipboard() })
        actionsRow.addView(makeButton("Tamper text now") { triggerTextTamper() })
        actionsCard.addView(actionsRow)

        val jsonCard = Ui.card(this).also { root.addView(it) }
        jsonCard.addView(Ui.titleRow(this, "Telemetry JSON"))
        jsonCard.addView(
            Ui.subtitle(
                this,
                "Exactly the bytes a backend would receive from DeviceIntelligence.collectJson(context).",
            ),
        )
        jsonView = TextView(this).apply {
            typeface = android.graphics.Typeface.MONOSPACE
            textSize = 11f
            setTextColor(Ui.Colors.MONO)
            setTextIsSelectable(true)
            text = "(collecting…)"
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = Ui.dp(this@MainActivity, 8) }
        }
        jsonCard.addView(jsonView)

        val logCard = Ui.card(this).also { root.addView(it) }
        logCard.addView(Ui.titleRow(this, "Event log"))
        logCard.addView(
            Ui.subtitle(
                this,
                "Last $eventLogLimit UI events. Logcat tag '$TAG' has the rest.",
            ),
        )
        eventLogView = TextView(this).apply {
            typeface = android.graphics.Typeface.MONOSPACE
            textSize = 11f
            setTextColor(Ui.Colors.MONO)
            text = "(no events yet)"
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = Ui.dp(this@MainActivity, 8) }
        }
        logCard.addView(eventLogView)

        return ScrollView(this).apply {
            setBackgroundColor(Ui.Colors.PAGE_BG)
            fitsSystemWindows = true
            addView(
                root,
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ),
            )
        }
    }

    // ---- collect & render --------------------------------------------------

    private fun runCollect(initial: Boolean) {
        // Collect off the main thread — it does ZIP I/O.
        Thread({
            val report = try {
                DeviceIntelligence.collect(this)
            } catch (t: Throwable) {
                Log.e(TAG, "DeviceIntelligence.collect threw", t)
                null
            }
            mainHandler.post {
                if (report == null) {
                    jsonView.text = "(collect failed — see logcat)"
                    appendEvent("collect failed")
                    return@post
                }
                lastReport = report
                lastJson = report.toJson()
                renderHero(report)
                renderSummaryChips(report)
                jsonView.text = lastJson
                val findingCount = report.summary.totalFindings
                val verb = if (initial) "initial collect" else "recollect"
                appendEvent("$verb done: $findingCount finding(s) in ${report.collectionDurationMs}ms")
                Log.i(JSON_TAG, lastJson)
            }
        }, "sample-collect").apply { isDaemon = true }.start()
    }

    private fun renderHero(report: TelemetryReport) {
        heroContainer.removeAllViews()
        val total = report.summary.totalFindings
        val critical = report.summary.findingsBySeverity[Severity.CRITICAL] ?: 0
        val high = report.summary.findingsBySeverity[Severity.HIGH] ?: 0

        // Tone is informational only — DeviceIntelligence is telemetry, not policy.
        // We pick a tone for legibility (red if anything CRITICAL,
        // amber if anything HIGH, gray otherwise) but the JSON is the
        // source of truth.
        val tone = when {
            critical > 0 -> Ui.Tone.BAD
            high > 0 -> Ui.Tone.WARN
            total > 0 -> Ui.Tone.INFO
            else -> Ui.Tone.OK
        }
        val (fg, bg) = when (tone) {
            Ui.Tone.OK -> Ui.Colors.GREEN to Ui.Colors.GREEN_BG
            Ui.Tone.BAD -> Ui.Colors.RED to Ui.Colors.RED_BG
            Ui.Tone.WARN -> Ui.Colors.AMBER to Ui.Colors.AMBER_BG
            Ui.Tone.INFO -> Ui.Colors.BLUE to Ui.Colors.BLUE_BG
            Ui.Tone.NEUTRAL -> Ui.Colors.GRAY to Ui.Colors.GRAY_BG
        }
        (heroContainer.background as android.graphics.drawable.GradientDrawable).setColor(bg)

        heroContainer.addView(
            TextView(this).apply {
                text = "DeviceIntelligence · ${report.libraryVersion}"
                textSize = 13f
                setTextColor(Ui.Colors.SUBTITLE)
            },
        )
        heroContainer.addView(
            TextView(this).apply {
                text = when {
                    total == 0 -> "0 findings"
                    total == 1 -> "1 finding"
                    else -> "$total findings"
                }
                textSize = 30f
                setTextColor(fg)
                typeface = android.graphics.Typeface.create(
                    android.graphics.Typeface.DEFAULT,
                    android.graphics.Typeface.BOLD,
                )
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { topMargin = Ui.dp(this@MainActivity, 4) }
            },
        )
        heroContainer.addView(
            TextView(this).apply {
                text = "${report.detectors.size} detectors · " +
                    "${report.collectionDurationMs} ms · " +
                    timeFmt.format(Date(report.collectedAtEpochMs))
                textSize = 13f
                setTextColor(Ui.Colors.SUBTITLE)
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { topMargin = Ui.dp(this@MainActivity, 6) }
            },
        )
    }

    private fun renderSummaryChips(report: TelemetryReport) {
        summaryChips.removeAllViews()
        val sev = report.summary.findingsBySeverity
        addChip(summaryChips, "critical", sev[Severity.CRITICAL] ?: 0, Ui.Tone.BAD)
        addChip(summaryChips, "high", sev[Severity.HIGH] ?: 0, Ui.Tone.WARN)
        addChip(summaryChips, "medium", sev[Severity.MEDIUM] ?: 0, Ui.Tone.INFO)
        addChip(summaryChips, "low", sev[Severity.LOW] ?: 0, Ui.Tone.NEUTRAL)
        addChip(
            summaryChips,
            "inconclusive",
            report.summary.detectorsInconclusive.size,
            Ui.Tone.NEUTRAL,
        )
        addChip(
            summaryChips,
            "errors",
            report.summary.detectorsErrored.size,
            Ui.Tone.BAD,
        )
    }

    private fun addChip(parent: LinearLayout, label: String, count: Int, tone: Ui.Tone) {
        val (fg, bg) = when (tone) {
            Ui.Tone.OK -> Ui.Colors.GREEN to Ui.Colors.GREEN_BG
            Ui.Tone.BAD -> Ui.Colors.RED to Ui.Colors.RED_BG
            Ui.Tone.WARN -> Ui.Colors.AMBER to Ui.Colors.AMBER_BG
            Ui.Tone.INFO -> Ui.Colors.BLUE to Ui.Colors.BLUE_BG
            Ui.Tone.NEUTRAL -> Ui.Colors.GRAY to Ui.Colors.GRAY_BG
        }
        val pad = Ui.dp(this, 8)
        val padV = Ui.dp(this, 4)
        val radius = Ui.dp(this, 999).toFloat()
        val drawable = android.graphics.drawable.GradientDrawable().apply {
            setColor(bg)
            cornerRadius = radius
        }
        val view = TextView(this).apply {
            text = "$label · $count"
            textSize = 11f
            setTextColor(fg)
            background = drawable
            setPadding(pad, padV, pad, padV)
        }
        val lp = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { rightMargin = Ui.dp(this@MainActivity, 6) }
        parent.addView(view, lp)
    }

    // ---- actions -----------------------------------------------------------

    private fun copyJsonToClipboard() {
        val json = lastJson
        if (json.isEmpty()) {
            toast("Nothing collected yet")
            return
        }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("DeviceIntelligence telemetry JSON", json))
        toast("JSON copied (${json.length} chars)")
        appendEvent("copied JSON to clipboard")
    }

    /**
     * Flip one byte of libdicore.so .text. The F11 watchdog will
     * notice on its next tick (~500ms); the very next collect will
     * include a `native_text_drift` finding.
     */
    private fun triggerTextTamper() {
        Thread({
            val target = try {
                SelfProtectTestRig.probeAddressInOwnText()
            } catch (t: Throwable) {
                Log.e(TAG, "probeAddressInOwnText threw", t)
                0L
            }
            if (target == 0L) {
                mainHandler.post { toast("probeAddressInOwnText returned 0") }
                return@Thread
            }
            val ok = try {
                SelfProtectTestRig.flipOneByteOfText(target)
            } catch (t: Throwable) {
                Log.e(TAG, "flipOneByteOfText threw", t)
                false
            }
            mainHandler.post {
                if (ok) {
                    appendEvent(
                        "tamper applied at 0x${target.toULong().toString(16)} — re-collect to see finding",
                    )
                    toast("Tampered .text — try Re-collect")
                } else {
                    toast("Tamper failed (mprotect)")
                }
            }
        }, "sample-tamper").apply { isDaemon = true }.start()
    }

    // ---- helpers -----------------------------------------------------------

    private fun makeButton(label: String, onClick: () -> Unit): Button {
        val pad = Ui.dp(this, 12)
        val padV = Ui.dp(this, 6)
        val radius = Ui.dp(this, 12).toFloat()
        val drawable = android.graphics.drawable.GradientDrawable().apply {
            setColor(Ui.Colors.BLUE_BG)
            cornerRadius = radius
        }
        return Button(this).apply {
            text = label
            textSize = 12f
            setTextColor(Ui.Colors.BLUE)
            background = drawable
            setPadding(pad, padV, pad, padV)
            isAllCaps = false
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { rightMargin = Ui.dp(this@MainActivity, 6) }
            setOnClickListener { onClick() }
        }
    }

    private fun toast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
    }

    private fun appendEvent(msg: String) {
        val line = "${timeFmt.format(Date())}  $msg"
        Log.i(TAG, msg)
        eventLog.addLast(line)
        while (eventLog.size > eventLogLimit) eventLog.removeFirst()
        eventLogView.text = eventLog.joinToString("\n")
    }

    private companion object {
        const val TAG = "DeviceIntelligence.Sample"
        const val JSON_TAG = "DeviceIntelligence.Json"
    }
}
