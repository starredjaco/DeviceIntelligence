package io.ssemaj.sample

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Tiny programmatic-UI toolkit for the sample app. Kept self-contained
 * (no AndroidX, no resources) so the sample stays a one-jar
 * smoke-test artifact rather than a full app project.
 *
 * Color palette is roughly Material You-ish but hard-coded — no theme
 * lookups. All sizes are dp-converted on the fly via [dp].
 */
internal object Ui {

    object Colors {
        const val PAGE_BG = 0xFFF6F7F9.toInt()
        const val CARD_BG = 0xFFFFFFFF.toInt()
        const val CARD_BORDER = 0xFFE3E5EA.toInt()
        const val TITLE = 0xFF111418.toInt()
        const val SUBTITLE = 0xFF53575E.toInt()
        const val MONO = 0xFF1F2328.toInt()
        const val MUTED = 0xFF7A7E86.toInt()
        const val GREEN = 0xFF1F7A3A.toInt()
        const val GREEN_BG = 0xFFE5F4EA.toInt()
        const val RED = 0xFFB3261E.toInt()
        const val RED_BG = 0xFFFCE7E5.toInt()
        const val AMBER = 0xFFA5560A.toInt()
        const val AMBER_BG = 0xFFFFF1DD.toInt()
        const val BLUE = 0xFF1A56A8.toInt()
        const val BLUE_BG = 0xFFE3EEFB.toInt()
        const val GRAY = 0xFF53575E.toInt()
        const val GRAY_BG = 0xFFEDEEF0.toInt()
    }

    enum class Tone { OK, BAD, WARN, INFO, NEUTRAL }

    private fun tonePair(t: Tone): Pair<Int, Int> = when (t) {
        Tone.OK -> Colors.GREEN to Colors.GREEN_BG
        Tone.BAD -> Colors.RED to Colors.RED_BG
        Tone.WARN -> Colors.AMBER to Colors.AMBER_BG
        Tone.INFO -> Colors.BLUE to Colors.BLUE_BG
        Tone.NEUTRAL -> Colors.GRAY to Colors.GRAY_BG
    }

    fun dp(context: Context, value: Int): Int =
        TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            value.toFloat(),
            context.resources.displayMetrics,
        ).toInt()

    /**
     * Vertical card container with a rounded white background and a
     * 1dp border in card-border gray. Adds a small bottom margin so
     * cards stack with breathing room.
     */
    fun card(context: Context): LinearLayout {
        val pad = dp(context, 16)
        val radius = dp(context, 14).toFloat()
        val border = dp(context, 1)

        val bg = GradientDrawable().apply {
            setColor(Colors.CARD_BG)
            cornerRadius = radius
            setStroke(border, Colors.CARD_BORDER)
        }
        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            background = bg
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply {
                bottomMargin = dp(context, 12)
            }
        }
    }

    /**
     * Hero banner: a tall, color-toned rounded panel intended for the
     * top-of-screen verdict summary. Returns the container so callers
     * can populate it with title/subtitle text.
     */
    fun heroBanner(context: Context, tone: Tone): LinearLayout {
        val (_, bg) = tonePair(tone)
        val radius = dp(context, 16).toFloat()
        val pad = dp(context, 18)
        val drawable = GradientDrawable().apply {
            setColor(bg)
            cornerRadius = radius
        }
        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            background = drawable
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply {
                bottomMargin = dp(context, 16)
            }
        }
    }

    fun title(context: Context, text: String): TextView = TextView(context).apply {
        this.text = text
        textSize = 18f
        setTextColor(Colors.TITLE)
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
    }

    fun subtitle(context: Context, text: String): TextView = TextView(context).apply {
        this.text = text
        textSize = 13f
        setTextColor(Colors.SUBTITLE)
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(context, 4) }
    }

    /**
     * Mono-spaced paragraph. Wrap-friendly. Used for technical fields
     * (hashes, addresses, paths) that should keep alignment.
     */
    fun mono(context: Context, text: String, color: Int = Colors.MONO): TextView =
        TextView(context).apply {
            this.text = text
            textSize = 11f
            setTextColor(color)
            typeface = Typeface.MONOSPACE
            setLineSpacing(0f, 1.15f)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(context, 4) }
        }

    /** Small inline pill (badge) to color-code state. */
    fun badge(context: Context, text: String, tone: Tone): TextView {
        val (fg, bg) = tonePair(tone)
        val pad = dp(context, 6)
        val padV = dp(context, 2)
        val radius = dp(context, 999).toFloat()
        val drawable = GradientDrawable().apply {
            setColor(bg)
            cornerRadius = radius
        }
        return TextView(context).apply {
            this.text = text.uppercase()
            textSize = 10.5f
            setTextColor(fg)
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setPadding(pad, padV, pad, padV)
            background = drawable
            includeFontPadding = false
        }
    }

    /**
     * Horizontal row that places the [title] flush-left and a list of
     * accessory views (typically badges) flush-right. Used for the
     * card title bar.
     */
    fun titleRow(
        context: Context,
        titleText: String,
        accessories: List<View> = emptyList(),
    ): LinearLayout {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        }
        row.addView(
            title(context, titleText).apply {
                layoutParams = LinearLayout.LayoutParams(
                    0,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    1f,
                )
            },
        )
        for ((i, acc) in accessories.withIndex()) {
            val lp = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
            if (i > 0) lp.leftMargin = dp(context, 6)
            acc.layoutParams = lp
            row.addView(acc)
        }
        return row
    }

    /**
     * Section divider between intra-card groups. A thin, full-width
     * 1dp gray line with vertical breathing room.
     */
    fun divider(context: Context): View = View(context).apply {
        setBackgroundColor(Colors.CARD_BORDER)
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(context, 1),
        ).apply {
            topMargin = dp(context, 10)
            bottomMargin = dp(context, 10)
        }
    }

    /**
     * A small section header inside a card, used to label e.g. the
     * "Regions" or "Protected methods" sub-list.
     */
    fun sectionLabel(context: Context, text: String): TextView = TextView(context).apply {
        this.text = text
        textSize = 12f
        setTextColor(Colors.MUTED)
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(context, 4) }
    }

    /**
     * Compact button. Uses a rounded color-toned background instead of
     * the platform default so it matches the rest of the cards.
     */
    fun button(context: Context, text: String, tone: Tone = Tone.INFO, onClick: () -> Unit): Button {
        val (fg, bg) = tonePair(tone)
        val drawable = GradientDrawable().apply {
            setColor(bg)
            cornerRadius = dp(context, 10).toFloat()
        }
        return Button(context).apply {
            this.text = text
            textSize = 12f
            isAllCaps = false
            setTextColor(fg)
            background = drawable
            stateListAnimator = null
            minHeight = dp(context, 40)
            setPadding(dp(context, 14), 0, dp(context, 14), 0)
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setOnClickListener { onClick() }
        }
    }

    /**
     * Horizontal layout of [buttons] that wraps onto multiple lines
     * via a vertical [LinearLayout] of horizontal lines. Each button
     * gets equal horizontal weight on its line. Used for card action
     * rows.
     */
    fun buttonRow(context: Context, buttons: List<Button>): LinearLayout {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(context, 12) }
        }
        for ((i, b) in buttons.withIndex()) {
            val lp = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f,
            )
            if (i > 0) lp.leftMargin = dp(context, 8)
            b.layoutParams = lp
            row.addView(b)
        }
        return row
    }

    /**
     * Convenience for small single-line key=value rows in a card body.
     * Renders as `key  value` with key in muted gray and value in
     * mono dark.
     */
    fun kv(context: Context, key: String, value: String): LinearLayout {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(context, 2) }
        }
        row.addView(
            TextView(context).apply {
                text = key
                textSize = 11.5f
                setTextColor(Colors.MUTED)
                layoutParams = LinearLayout.LayoutParams(dp(context, 130), ViewGroup.LayoutParams.WRAP_CONTENT)
            },
        )
        row.addView(
            TextView(context).apply {
                text = value
                textSize = 11.5f
                setTextColor(Colors.MONO)
                typeface = Typeface.MONOSPACE
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                )
            },
        )
        return row
    }

    /**
     * Render an opaque 64-bit value as `0x%016x`. Centralised so we
     * stay consistent across cards.
     */
    fun hex64(value: Long): String = "0x%016x".format(value)
}
