"""
BugBunny Hackathon Presentation Generator
Team CSIS - Unifonic AI Hackathon 2025

Generates a 14-slide PowerPoint presentation with neon green on black theme.
Output: BugBunny_Hackathon.pptx

All statistics are sourced from verifiable studies:
- NIST SP 500-326 (SATE V, 2018): SAST false positive rates 3-78%
- Ghost Security "Exorcising the SAST Demons" (2025): 91%+ false positives
- Ponemon/Exabeam (2019): 25% of security team time on false positives
- Contrast Security (2021): 3+ hrs per false positive to investigate
- IBM/Ponemon Cost of a Data Breach (2024): $4.88M global average
- 87->12 figure is from BugBunny's demo scan pipeline
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

# =============================================================================
# CONSTANTS
# =============================================================================
SLIDE_WIDTH = Inches(13.333)
SLIDE_HEIGHT = Inches(7.5)

COLOR_BLACK = RGBColor(0x00, 0x00, 0x00)
COLOR_GREEN = RGBColor(0x00, 0xE6, 0x76)
COLOR_WHITE = RGBColor(0xFF, 0xFF, 0xFF)
COLOR_MUTED = RGBColor(0xAA, 0xAA, 0xAA)
COLOR_CARD = RGBColor(0x11, 0x11, 0x11)
COLOR_DARK_GREEN = RGBColor(0x00, 0x80, 0x40)

FONT_NAME = "Calibri"
LOGO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend", "public", "icon.png")

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "BugBunny_Hackathon.pptx")


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def set_slide_bg(slide, color=COLOR_BLACK):
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = color


def add_textbox(slide, left, top, width, height, text, font_size=18,
                color=COLOR_WHITE, bold=False, alignment=PP_ALIGN.LEFT,
                font_name=FONT_NAME, anchor=MSO_ANCHOR.TOP):
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    tf.auto_size = None
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(font_size)
    p.font.color.rgb = color
    p.font.bold = bold
    p.font.name = font_name
    p.alignment = alignment
    return txBox


def add_multiline_textbox(slide, left, top, width, height, lines, default_size=18,
                          default_color=COLOR_WHITE, default_bold=False,
                          alignment=PP_ALIGN.LEFT, line_spacing=1.2):
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    tf.auto_size = None
    for i, line_info in enumerate(lines):
        if isinstance(line_info, str):
            line_info = {"text": line_info}
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.text = line_info.get("text", "")
        p.font.size = Pt(line_info.get("size", default_size))
        p.font.color.rgb = line_info.get("color", default_color)
        p.font.bold = line_info.get("bold", default_bold)
        p.font.name = FONT_NAME
        p.alignment = line_info.get("alignment", alignment)
        p.space_after = Pt(line_info.get("space_after", 4))
        p.space_before = Pt(line_info.get("space_before", 0))
    return txBox


def add_card(slide, left, top, width, height, border_color=COLOR_GREEN):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = COLOR_CARD
    shape.line.color.rgb = border_color
    shape.line.width = Pt(1.5)
    shape.shadow.inherit = False
    shape.adjustments[0] = 0.02
    return shape


def add_rect(slide, left, top, width, height, fill_color=COLOR_CARD, border_color=None, border_width=1.5):
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    if border_color:
        shape.line.color.rgb = border_color
        shape.line.width = Pt(border_width)
    else:
        shape.line.fill.background()
    shape.shadow.inherit = False
    return shape


def add_rounded_rect(slide, left, top, width, height, fill_color=COLOR_CARD, border_color=COLOR_GREEN, border_width=1.5):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    if border_color:
        shape.line.color.rgb = border_color
        shape.line.width = Pt(border_width)
    else:
        shape.line.fill.background()
    shape.shadow.inherit = False
    shape.adjustments[0] = 0.05
    return shape


def add_pill(slide, left, top, width, height, fill_color=COLOR_GREEN, border_color=None):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    if border_color:
        shape.line.color.rgb = border_color
        shape.line.width = Pt(1.5)
    else:
        shape.line.fill.background()
    shape.shadow.inherit = False
    shape.adjustments[0] = 0.5
    return shape


def add_circle(slide, left, top, size, fill_color=COLOR_GREEN, border_color=None):
    shape = slide.shapes.add_shape(MSO_SHAPE.OVAL, left, top, size, size)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    if border_color:
        shape.line.color.rgb = border_color
        shape.line.width = Pt(1)
    else:
        shape.line.fill.background()
    shape.shadow.inherit = False
    return shape


def add_arrow_right(slide, left, top, width, height, fill_color=COLOR_GREEN):
    shape = slide.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    shape.line.fill.background()
    shape.shadow.inherit = False
    return shape


def set_speaker_notes(slide, notes_text):
    notes_slide = slide.notes_slide
    notes_slide.notes_text_frame.text = notes_text


def add_footer_bar(slide, text="Team CSIS  |  BugBunny  |  Unifonic AI Hackathon 2025"):
    add_rect(slide, Inches(0), Inches(7.05), SLIDE_WIDTH, Inches(0.45),
             fill_color=RGBColor(0x0A, 0x0A, 0x0A), border_color=None)
    add_textbox(slide, Inches(0.5), Inches(7.08), Inches(12), Inches(0.35),
                text, font_size=10, color=COLOR_MUTED, alignment=PP_ALIGN.CENTER)


def add_slide_number(slide, number):
    add_textbox(slide, Inches(12.5), Inches(7.08), Inches(0.7), Inches(0.35),
                str(number), font_size=10, color=COLOR_MUTED, alignment=PP_ALIGN.RIGHT)


def add_section_label(slide, text):
    add_pill(slide, Inches(0.6), Inches(0.3), Inches(len(text) * 0.12 + 0.4), Inches(0.32),
             fill_color=RGBColor(0x00, 0x33, 0x1A), border_color=COLOR_GREEN)
    add_textbox(slide, Inches(0.6), Inches(0.3), Inches(len(text) * 0.12 + 0.4), Inches(0.32),
                text, font_size=10, color=COLOR_GREEN, bold=True, alignment=PP_ALIGN.CENTER)


# =============================================================================
# SLIDE BUILDERS
# =============================================================================

def build_slide_1(prs):
    """Hook slide."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_rect(slide, Inches(0), Inches(0), SLIDE_WIDTH, Inches(0.04), fill_color=COLOR_GREEN)

    if os.path.exists(LOGO_PATH):
        slide.shapes.add_picture(LOGO_PATH, Inches(5.67), Inches(0.8), Inches(2), Inches(2))

    add_textbox(slide, Inches(1), Inches(3.0), Inches(11.333), Inches(1.2),
                '"What if most of your security alerts\nwere a waste of time?"',
                font_size=40, color=COLOR_GREEN, bold=True, alignment=PP_ALIGN.CENTER)

    add_textbox(slide, Inches(1), Inches(4.4), Inches(11.333), Inches(0.6),
                "For most teams, they are.", font_size=28, color=COLOR_WHITE, bold=True,
                alignment=PP_ALIGN.CENTER)

    add_textbox(slide, Inches(1), Inches(5.1), Inches(11.333), Inches(0.5),
                "Meet BugBunny \u2014 the AI-powered security platform that eliminates the noise.",
                font_size=18, color=COLOR_MUTED, alignment=PP_ALIGN.CENTER)

    add_pill(slide, Inches(4.5), Inches(5.9), Inches(2), Inches(0.38),
             fill_color=RGBColor(0x00, 0x33, 0x1A), border_color=COLOR_GREEN)
    add_textbox(slide, Inches(4.5), Inches(5.9), Inches(2), Inches(0.38),
                "Track 1: AI Apps", font_size=11, color=COLOR_GREEN, bold=True,
                alignment=PP_ALIGN.CENTER)

    add_pill(slide, Inches(6.8), Inches(5.9), Inches(2.2), Inches(0.38),
             fill_color=RGBColor(0x00, 0x33, 0x1A), border_color=COLOR_GREEN)
    add_textbox(slide, Inches(6.8), Inches(5.9), Inches(2.2), Inches(0.38),
                "Track 4: Security", font_size=11, color=COLOR_GREEN, bold=True,
                alignment=PP_ALIGN.CENTER)

    add_textbox(slide, Inches(1), Inches(6.5), Inches(11.333), Inches(0.5),
                "Team CSIS", font_size=22, color=COLOR_WHITE, bold=True,
                alignment=PP_ALIGN.CENTER)

    add_footer_bar(slide)
    add_slide_number(slide, 1)

    set_speaker_notes(slide, """[0:00 - 0:45] HOOK SLIDE

Opening: "What if I told you that most of your security alerts were a complete waste of time?"

Pause. Let it sink in.

"That's the reality for development teams running static analysis today. Research consistently shows that the majority of SAST findings are false positives. Your security team is drowning in noise, and the real vulnerabilities are hiding in plain sight."

"Today, we're going to show you how BugBunny changes that."

Transition: "Let me show you exactly how bad the problem is..."
""")


def build_slide_2(prs):
    """The False Positive Tax -- sourced statistics."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "THE PROBLEM")

    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "The False Positive Tax", font_size=36, color=COLOR_GREEN, bold=True)
    add_textbox(slide, Inches(0.6), Inches(1.45), Inches(12), Inches(0.4),
                "Every engineering team pays it. The research quantifies how much.",
                font_size=16, color=COLOR_MUTED)

    # Three stat cards -- ALL sourced
    card_data = [
        {
            "stat": "Up to 91%",
            "label": "of SAST findings are\nfalse positives",
            "sublabel": "Ghost Security, 2025"
        },
        {
            "stat": "25%",
            "label": "of security team time\nspent chasing false positives",
            "sublabel": "Ponemon / Exabeam, 2019"
        },
        {
            "stat": "$4.88M",
            "label": "average cost of\na data breach globally",
            "sublabel": "IBM / Ponemon, 2024"
        },
    ]

    for i, card in enumerate(card_data):
        x = Inches(0.6 + i * 4.1)
        y = Inches(2.2)
        w = Inches(3.8)
        h = Inches(2.5)

        add_card(slide, x, y, w, h)
        add_textbox(slide, x + Inches(0.3), y + Inches(0.3), w - Inches(0.6), Inches(0.8),
                    card["stat"], font_size=44, color=COLOR_GREEN, bold=True, alignment=PP_ALIGN.CENTER)
        add_textbox(slide, x + Inches(0.3), y + Inches(1.2), w - Inches(0.6), Inches(0.8),
                    card["label"], font_size=16, color=COLOR_WHITE, alignment=PP_ALIGN.CENTER)
        add_textbox(slide, x + Inches(0.3), y + Inches(2.0), w - Inches(0.6), Inches(0.35),
                    card["sublabel"], font_size=11, color=COLOR_MUTED, alignment=PP_ALIGN.CENTER)

    # Pain points with source context
    pain_points = [
        "\u26a0  Alert fatigue leads to real vulnerabilities being ignored",
        "\u26a0  Developers lose trust in security tools and disable them",
        "\u26a0  Security teams become bottlenecks, not enablers",
        "\u26a0  NIST SATE V (2018): SAST false positive rates ranged 3\u201378% across tools and languages",
    ]
    for i, point in enumerate(pain_points):
        add_textbox(slide, Inches(0.8), Inches(5.0 + i * 0.42), Inches(11), Inches(0.4),
                    point, font_size=15, color=COLOR_WHITE)

    # Source footnote
    add_textbox(slide, Inches(0.6), Inches(6.65), Inches(12), Inches(0.35),
                "Sources: Ghost Security 2025 | Ponemon/Exabeam 2019 | IBM Cost of a Data Breach 2024 | NIST SP 500-326",
                font_size=9, color=RGBColor(0x66, 0x66, 0x66), alignment=PP_ALIGN.LEFT)

    add_footer_bar(slide)
    add_slide_number(slide, 2)

    set_speaker_notes(slide, """[0:45 - 1:45] THE PROBLEM

"Let's talk numbers -- and these are from real research, not marketing."

"Ghost Security's 2025 report scanned real open-source projects on GitHub and found that over 91 percent of SAST findings were false positives. For Python Flask apps, it was as high as 99.5 percent."

"Ponemon Institute and Exabeam found in 2019 that security teams spend approximately 25 percent of their time chasing false positives. That's a quarter of your security team's capacity wasted on noise."

"And when real vulnerabilities DO slip through? IBM's 2024 Cost of a Data Breach report puts the global average at $4.88 million per breach. In the US, it's over $9 million."

"NIST's own SATE V study tested ten SAST tools and found false positive rates ranging from 3 to 78 percent depending on tool and language."

"This creates a vicious cycle: alert fatigue, tool distrust, and real vulnerabilities slipping through."

Transition: "Let me show you what BugBunny does about this..."
""")


def build_slide_3(prs):
    """87 -> 12 -- The transformation reveal (framed as demo results)."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "DEMO RESULTS")

    # Title
    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "87 \u2192 12", font_size=56, color=COLOR_GREEN, bold=True,
                alignment=PP_ALIGN.CENTER)
    add_textbox(slide, Inches(0.6), Inches(1.55), Inches(12), Inches(0.4),
                "In our demo scan: 87 raw SAST findings reduced to 12 confirmed vulnerabilities",
                font_size=18, color=COLOR_MUTED, alignment=PP_ALIGN.CENTER)

    # Before section
    add_textbox(slide, Inches(1.0), Inches(2.3), Inches(5), Inches(0.5),
                "BEFORE: Raw SAST Output", font_size=16, color=RGBColor(0xFF, 0x44, 0x44), bold=True)

    dot_size = Inches(0.18)
    cols = 15
    for idx in range(87):
        row = idx // cols
        col = idx % cols
        x = Inches(1.0) + col * Inches(0.34)
        y = Inches(2.85) + row * Inches(0.34)
        is_real = idx < 12
        dot_color = COLOR_GREEN if is_real else RGBColor(0xFF, 0x44, 0x44)
        add_circle(slide, x, y, dot_size, fill_color=dot_color)

    # After section
    add_textbox(slide, Inches(7.5), Inches(2.3), Inches(5), Inches(0.5),
                "AFTER: BugBunny Pipeline", font_size=16, color=COLOR_GREEN, bold=True)

    for idx in range(12):
        row = idx // 4
        col = idx % 4
        x = Inches(8.0) + col * Inches(0.5)
        y = Inches(2.85) + row * Inches(0.5)
        add_circle(slide, x, y, Inches(0.3), fill_color=COLOR_GREEN)

    add_arrow_right(slide, Inches(6.2), Inches(3.5), Inches(1.0), Inches(0.5), fill_color=COLOR_GREEN)

    # Legend
    add_circle(slide, Inches(7.5), Inches(4.8), Inches(0.15), fill_color=COLOR_GREEN)
    add_textbox(slide, Inches(7.8), Inches(4.75), Inches(2), Inches(0.3),
                "Confirmed vulnerability", font_size=12, color=COLOR_WHITE)
    add_circle(slide, Inches(7.5), Inches(5.1), Inches(0.15), fill_color=RGBColor(0xFF, 0x44, 0x44))
    add_textbox(slide, Inches(7.8), Inches(5.05), Inches(2), Inches(0.3),
                "False positive (eliminated)", font_size=12, color=COLOR_MUTED)

    # Three stat pills -- honest framing
    stats = [
        ("86% Noise Removed", "75 of 87 findings eliminated"),
        ("Seconds per Finding", "AI triage vs hours of manual review"),
        ("Zero Missed", "all real vulnerabilities retained"),
    ]
    for i, (stat, desc) in enumerate(stats):
        x = Inches(1.0 + i * 4.0)
        add_card(slide, x, Inches(5.7), Inches(3.6), Inches(1.0))
        add_textbox(slide, x + Inches(0.2), Inches(5.8), Inches(3.2), Inches(0.5),
                    stat, font_size=22, color=COLOR_GREEN, bold=True, alignment=PP_ALIGN.CENTER)
        add_textbox(slide, x + Inches(0.2), Inches(6.2), Inches(3.2), Inches(0.35),
                    desc, font_size=13, color=COLOR_MUTED, alignment=PP_ALIGN.CENTER)

    add_footer_bar(slide)
    add_slide_number(slide, 3)

    set_speaker_notes(slide, """[1:45 - 2:35] DEMO RESULTS

"Here's what BugBunny does in practice. We ran our full pipeline on a test codebase and this is the result."

"On the left: 87 dots. That's the raw SAST output. Every single one of those would land in a developer's queue for manual review."

"The red dots are false positives. The green dots are real, exploitable vulnerabilities. Notice how the real issues are completely buried in noise."

"On the right -- after BugBunny's intelligence pipeline -- 12 confirmed vulnerabilities. Each one analyzed by AI, verified for exploitability, and where possible, validated at runtime."

"That's 86% of the noise eliminated. And critically, zero real vulnerabilities were missed in this scan."

"The key difference: AI triage processes each finding in seconds. Manual review of a single false positive takes 3 or more hours according to Contrast Security's 2021 research."

Transition: "So how does BugBunny achieve this? Let me walk you through the pipeline..."
""")


def build_slide_4(prs):
    """How BugBunny Works -- The Intelligence Pipeline."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "ARCHITECTURE")

    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "How BugBunny Works", font_size=36, color=COLOR_GREEN, bold=True)
    add_textbox(slide, Inches(0.6), Inches(1.4), Inches(12), Inches(0.4),
                "The 7-Stage Intelligence Pipeline", font_size=18, color=COLOR_MUTED)

    # Pipeline stages -- accurate to codebase (Semgrep only, no Bandit)
    stages = [
        ("1", "SAST\nScan", "Semgrep with\n3,000+ rules"),
        ("2", "Context\nExtraction", "AST parsing,\ndata flow analysis"),
        ("3", "AI\nTriage", "LLM analyzes\nexploitability"),
        ("4", "Reachability\nAnalysis", "Call graph +\nentry point check"),
        ("5", "Targeted\nDAST", "ZAP validates\nexploitable findings"),
        ("6", "Correlation\nEngine", "Cross-reference\nall evidence"),
        ("7", "Action\nLayer", "AutoFix, Report,\nPinecone store"),
    ]

    stage_width = Inches(1.45)
    arrow_width = Inches(0.3)
    total_stages = len(stages)
    total_width = total_stages * stage_width + (total_stages - 1) * arrow_width
    start_x = (SLIDE_WIDTH - total_width) // 2

    for i, (num, name, desc) in enumerate(stages):
        x = start_x + i * (stage_width + arrow_width)
        y = Inches(2.2)

        add_rounded_rect(slide, x, y, stage_width, Inches(1.6),
                         fill_color=COLOR_CARD, border_color=COLOR_GREEN)

        add_circle(slide, x + stage_width // 2 - Inches(0.18), y - Inches(0.18),
                   Inches(0.36), fill_color=COLOR_GREEN)
        add_textbox(slide, x + stage_width // 2 - Inches(0.18), y - Inches(0.16),
                    Inches(0.36), Inches(0.36), num,
                    font_size=14, color=COLOR_BLACK, bold=True, alignment=PP_ALIGN.CENTER)

        add_textbox(slide, x + Inches(0.05), y + Inches(0.25), stage_width - Inches(0.1), Inches(0.65),
                    name, font_size=12, color=COLOR_WHITE, bold=True, alignment=PP_ALIGN.CENTER)

        add_textbox(slide, x + Inches(0.05), y + Inches(0.95), stage_width - Inches(0.1), Inches(0.55),
                    desc, font_size=9, color=COLOR_MUTED, alignment=PP_ALIGN.CENTER)

        if i < total_stages - 1:
            arrow_x = x + stage_width + Inches(0.02)
            add_textbox(slide, arrow_x, y + Inches(0.55), arrow_width, Inches(0.4),
                        "\u25B6", font_size=18, color=COLOR_GREEN, alignment=PP_ALIGN.CENTER)

    # Bottom detail cards
    detail_cards = [
        ("Input", "Source code repository\nGitHub integration\nMultiple language support"),
        ("Intelligence", "Context-aware analysis\nSemantic deduplication\nHistorical learning via Pinecone"),
        ("Output", "Confirmed vulnerabilities only\nAI-generated fix suggestions\nPDF compliance reports"),
    ]

    for i, (title, content) in enumerate(detail_cards):
        x = Inches(0.8 + i * 4.1)
        y = Inches(4.4)
        w = Inches(3.8)
        h = Inches(2.2)

        add_card(slide, x, y, w, h)
        add_textbox(slide, x + Inches(0.25), y + Inches(0.15), w - Inches(0.5), Inches(0.4),
                    title, font_size=16, color=COLOR_GREEN, bold=True)
        add_textbox(slide, x + Inches(0.25), y + Inches(0.6), w - Inches(0.5), Inches(1.4),
                    content, font_size=13, color=COLOR_WHITE)

    add_footer_bar(slide)
    add_slide_number(slide, 4)

    set_speaker_notes(slide, """[2:35 - 3:50] THE INTELLIGENCE PIPELINE

"BugBunny isn't just another scanner. It's a 7-stage intelligence pipeline that mimics how a senior security engineer would review findings."

Walk through each stage:
"Stage 1: SAST scanning with Semgrep and its library of over 3,000 rules. We cast a wide net to minimize blind spots."

"Stage 2: Context extraction. We parse the AST, trace data flows, and understand HOW the code actually works -- not just pattern match."

"Stage 3: AI Triage. This is our core differentiator. An LLM analyzes each finding with full code context and determines if it's actually exploitable."

"Stage 4: Reachability analysis. Can an attacker actually REACH this code? We trace call graphs from public entry points."

"Stage 5: Targeted DAST. For high-confidence findings, we use ZAP to actually try to exploit them at runtime. Proof, not theory."

"Stage 6: Correlation engine. We cross-reference evidence from all stages to produce a final confidence score."

"Stage 7: Action layer. AutoFix generates patches, we create PDF reports, and findings get stored in Pinecone for cross-project learning."

Transition: "Let me deep-dive into two of our most innovative stages..."
""")


def build_slide_5(prs):
    """Not Just Static. Proven Exploitable. -- Targeted DAST."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "KEY DIFFERENTIATOR")

    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "Not Just Static. Proven Exploitable.", font_size=36, color=COLOR_GREEN, bold=True)
    add_textbox(slide, Inches(0.6), Inches(1.4), Inches(12), Inches(0.4),
                "Targeted DAST validates high-confidence SAST findings at runtime",
                font_size=16, color=COLOR_MUTED)

    # Left side -- SAST Finding
    add_card(slide, Inches(0.6), Inches(2.1), Inches(5.8), Inches(3.2))
    add_textbox(slide, Inches(0.9), Inches(2.25), Inches(5.2), Inches(0.4),
                "SAST Finding (Static)", font_size=18, color=RGBColor(0xFF, 0xAA, 0x00), bold=True)

    sast_lines = [
        {"text": "SQL Injection in /api/users/search", "size": 14, "color": COLOR_WHITE, "bold": True},
        {"text": "", "size": 6},
        {"text": 'query = f"SELECT * FROM users WHERE name = \'{input}\'"', "size": 12, "color": RGBColor(0xFF, 0x79, 0x79)},
        {"text": "", "size": 6},
        {"text": "\u26a0 Severity: HIGH (static estimate)", "size": 13, "color": RGBColor(0xFF, 0xAA, 0x00)},
        {"text": "\u2753 But is this endpoint reachable?", "size": 13, "color": COLOR_MUTED},
        {"text": "\u2753 Is the input actually user-controlled?", "size": 13, "color": COLOR_MUTED},
        {"text": "\u2753 Are there middleware sanitizers?", "size": 13, "color": COLOR_MUTED},
    ]
    add_multiline_textbox(slide, Inches(0.9), Inches(2.7), Inches(5.2), Inches(2.5), sast_lines)

    add_arrow_right(slide, Inches(6.55), Inches(3.4), Inches(0.6), Inches(0.4), fill_color=COLOR_GREEN)

    # Right side -- DAST Proof
    add_card(slide, Inches(7.3), Inches(2.1), Inches(5.5), Inches(3.2))
    add_textbox(slide, Inches(7.6), Inches(2.25), Inches(5.0), Inches(0.4),
                "DAST Proof (Runtime)", font_size=18, color=COLOR_GREEN, bold=True)

    dast_lines = [
        {"text": "ZAP Targeted Scan Result", "size": 14, "color": COLOR_WHITE, "bold": True},
        {"text": "", "size": 6},
        {"text": "GET /api/users/search?name=' OR 1=1 --", "size": 12, "color": COLOR_GREEN},
        {"text": "Response: 200 OK | All user records returned", "size": 12, "color": RGBColor(0xFF, 0x44, 0x44)},
        {"text": "", "size": 6},
        {"text": "\u2705 CONFIRMED EXPLOITABLE", "size": 14, "color": COLOR_GREEN, "bold": True},
        {"text": "\u2191 Confidence: HIGH \u2192 CRITICAL", "size": 13, "color": COLOR_GREEN},
    ]
    add_multiline_textbox(slide, Inches(7.6), Inches(2.7), Inches(5.0), Inches(2.5), dast_lines)

    # Confidence escalation table
    add_textbox(slide, Inches(0.6), Inches(5.5), Inches(12), Inches(0.4),
                "Confidence Escalation Matrix", font_size=16, color=COLOR_GREEN, bold=True)

    add_rect(slide, Inches(0.6), Inches(5.95), Inches(12.1), Inches(0.38),
             fill_color=RGBColor(0x00, 0x33, 0x1A))
    headers = ["SAST Only", "SAST + Context", "SAST + AI Triage", "SAST + AI + DAST"]
    for i, h in enumerate(headers):
        add_textbox(slide, Inches(0.6 + i * 3.025), Inches(5.95), Inches(3.025), Inches(0.38),
                    h, font_size=12, color=COLOR_GREEN, bold=True, alignment=PP_ALIGN.CENTER)

    add_rect(slide, Inches(0.6), Inches(6.33), Inches(12.1), Inches(0.38),
             fill_color=COLOR_CARD, border_color=RGBColor(0x33, 0x33, 0x33))
    values = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    value_colors = [RGBColor(0xFF, 0xAA, 0x00), RGBColor(0xFF, 0xCC, 0x00), COLOR_GREEN, COLOR_GREEN]
    for i, (v, c) in enumerate(zip(values, value_colors)):
        add_textbox(slide, Inches(0.6 + i * 3.025), Inches(6.33), Inches(3.025), Inches(0.38),
                    v, font_size=12, color=c, bold=True, alignment=PP_ALIGN.CENTER)

    add_footer_bar(slide)
    add_slide_number(slide, 5)

    set_speaker_notes(slide, """[3:50 - 5:00] TARGETED DAST

"This is one of our biggest differentiators. Most tools stop at static analysis. BugBunny doesn't just FIND potential vulnerabilities -- it PROVES they're exploitable."

"On the left, a typical SAST finding: SQL injection in a search endpoint. But static analysis alone can't answer the critical questions: Is this endpoint reachable? Is the input user-controlled? Are there sanitizers?"

"On the right -- BugBunny's targeted DAST. We spin up the application in a Docker container, and ZAP actually TRIES to exploit the finding. In this example, it confirms the SQL injection is exploitable."

"The confidence escalation: Each stage adds evidence. SAST alone is low confidence. Add context, medium. Add AI triage, high. Add runtime DAST proof, and you have critical-level confidence."

"This is real ZAP integration -- the service runs as a Docker container alongside our backend."

Transition: "Now let me show you how the AI triage engine works..."
""")


def build_slide_6(prs):
    """AI That Reads Code Like a Security Engineer."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "AI ENGINE")

    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "AI That Reads Code Like a Security Engineer",
                font_size=34, color=COLOR_GREEN, bold=True)
    add_textbox(slide, Inches(0.6), Inches(1.4), Inches(12), Inches(0.4),
                "LLM analyzes each finding with full code context, data flow, and security semantics",
                font_size=15, color=COLOR_MUTED)

    # Left side -- Prompt Template
    add_card(slide, Inches(0.6), Inches(2.0), Inches(6.0), Inches(4.4))
    add_textbox(slide, Inches(0.9), Inches(2.15), Inches(5.4), Inches(0.35),
                "AI Triage Prompt (Simplified)", font_size=15, color=COLOR_GREEN, bold=True)

    prompt_lines = [
        {"text": "You are a security engineer reviewing a SAST finding.", "size": 11, "color": COLOR_MUTED},
        {"text": "", "size": 4},
        {"text": "Finding: SQL Injection in user_search()", "size": 12, "color": COLOR_WHITE, "bold": True},
        {"text": "File: api/routes/users.py:47", "size": 11, "color": COLOR_MUTED},
        {"text": "Severity: HIGH", "size": 11, "color": RGBColor(0xFF, 0xAA, 0x00)},
        {"text": "", "size": 4},
        {"text": "Code Context (50 lines surrounding):", "size": 12, "color": COLOR_WHITE, "bold": True},
        {"text": "  def user_search(request):", "size": 11, "color": RGBColor(0x79, 0xC0, 0xFF)},
        {"text": "    name = request.args.get('name')", "size": 11, "color": RGBColor(0x79, 0xC0, 0xFF)},
        {"text": "    query = f\"SELECT * FROM users", "size": 11, "color": RGBColor(0xFF, 0x79, 0x79)},
        {"text": "            WHERE name = '{name}'\"", "size": 11, "color": RGBColor(0xFF, 0x79, 0x79)},
        {"text": "", "size": 4},
        {"text": "Data Flow: request.args \u2192 name \u2192 query \u2192 db.execute()", "size": 11, "color": COLOR_WHITE},
        {"text": "Entry Point: /api/users/search (public, no auth)", "size": 11, "color": COLOR_WHITE},
        {"text": "Sanitization: None detected", "size": 11, "color": RGBColor(0xFF, 0x44, 0x44)},
        {"text": "", "size": 4},
        {"text": "Analyze: Is this exploitable? Adjust severity.", "size": 12, "color": COLOR_GREEN, "bold": True},
    ]
    add_multiline_textbox(slide, Inches(0.9), Inches(2.55), Inches(5.4), Inches(3.7), prompt_lines)

    # Right side -- AI Response
    add_card(slide, Inches(6.9), Inches(2.0), Inches(5.9), Inches(4.4))
    add_textbox(slide, Inches(7.2), Inches(2.15), Inches(5.3), Inches(0.35),
                "AI Response (Structured JSON)", font_size=15, color=COLOR_GREEN, bold=True)

    response_lines = [
        {"text": "{", "size": 11, "color": COLOR_MUTED},
        {"text": '  "is_exploitable": true,', "size": 11, "color": COLOR_GREEN},
        {"text": '  "adjusted_severity": "CRITICAL",', "size": 11, "color": RGBColor(0xFF, 0x44, 0x44)},
        {"text": '  "confidence": 0.95,', "size": 11, "color": COLOR_WHITE},
        {"text": '  "reasoning": "User input flows', "size": 11, "color": COLOR_WHITE},
        {"text": '    directly into SQL query without', "size": 11, "color": COLOR_WHITE},
        {"text": '    any sanitization or parameterization.', "size": 11, "color": COLOR_WHITE},
        {"text": '    Endpoint is publicly accessible,', "size": 11, "color": COLOR_WHITE},
        {"text": '    no authentication required.",', "size": 11, "color": COLOR_WHITE},
        {"text": '  "attack_vector": "GET /api/users/', "size": 11, "color": RGBColor(0xFF, 0x79, 0x79)},
        {"text": "    search?name=' OR 1=1 --\",", "size": 11, "color": RGBColor(0xFF, 0x79, 0x79)},
        {"text": '  "fix_suggestion": "Use parameterized', "size": 11, "color": RGBColor(0x79, 0xC0, 0xFF)},
        {"text": '    queries: db.execute(sql, [name])"', "size": 11, "color": RGBColor(0x79, 0xC0, 0xFF)},
        {"text": "}", "size": 11, "color": COLOR_MUTED},
    ]
    add_multiline_textbox(slide, Inches(7.2), Inches(2.55), Inches(5.3), Inches(3.7), response_lines)

    # Bottom callout
    add_pill(slide, Inches(3.5), Inches(6.55), Inches(6.5), Inches(0.4),
             fill_color=RGBColor(0x00, 0x33, 0x1A), border_color=COLOR_GREEN)
    add_textbox(slide, Inches(3.5), Inches(6.55), Inches(6.5), Inches(0.4),
                "Not just severity \u2014 reasoning, attack vectors, and fix suggestions in one response",
                font_size=12, color=COLOR_GREEN, bold=True, alignment=PP_ALIGN.CENTER)

    add_footer_bar(slide)
    add_slide_number(slide, 6)

    set_speaker_notes(slide, """[5:00 - 6:00] AI TRIAGE ENGINE

"Here's how the AI actually works. On the left, the prompt we send to the LLM. It's not just 'is this a vulnerability?' -- we provide FULL context."

"We include the finding details, 50 lines of surrounding code, the complete data flow from input to sink, whether the entry point is public, and what sanitization exists."

"On the right, the structured JSON response. It's not a simple yes/no -- it includes exploitability assessment, adjusted severity, confidence score, detailed reasoning, a concrete attack vector, AND a fix suggestion."

"Our architecture is LLM-agnostic via OpenRouter -- we can swap between models based on cost, speed, or accuracy needs. The structured output format stays consistent regardless of which model handles the triage."

"In this example, the AI escalated severity from HIGH to CRITICAL because the input flows directly into SQL without sanitization and the endpoint is public. That's analysis that would take a human security engineer 15-20 minutes. Our AI does it in seconds."

Transition: "Now let me show you this in action..."
""")


def build_slide_7a(prs):
    """Demo: Dashboard Overview."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "LIVE DEMO")

    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "Product Walkthrough: Dashboard", font_size=34, color=COLOR_GREEN, bold=True)

    # Top stats
    dashboard_stats = [
        ("Total Scans", "24"),
        ("Active Issues", "12"),
        ("Fixed This Week", "8"),
        ("Risk Score", "B+"),
    ]
    for i, (label, value) in enumerate(dashboard_stats):
        x = Inches(0.6 + i * 3.1)
        add_card(slide, x, Inches(1.7), Inches(2.8), Inches(1.3))
        add_textbox(slide, x + Inches(0.2), Inches(1.85), Inches(2.4), Inches(0.3),
                    label, font_size=12, color=COLOR_MUTED)
        add_textbox(slide, x + Inches(0.2), Inches(2.2), Inches(2.4), Inches(0.6),
                    value, font_size=36, color=COLOR_GREEN, bold=True, alignment=PP_ALIGN.CENTER)

    # Severity breakdown
    add_card(slide, Inches(0.6), Inches(3.3), Inches(5.8), Inches(3.2))
    add_textbox(slide, Inches(0.9), Inches(3.45), Inches(5.2), Inches(0.35),
                "Findings by Severity", font_size=16, color=COLOR_GREEN, bold=True)

    severities = [
        ("CRITICAL", "3", RGBColor(0xFF, 0x44, 0x44), Inches(3.5)),
        ("HIGH", "5", RGBColor(0xFF, 0xAA, 0x00), Inches(2.8)),
        ("MEDIUM", "2", RGBColor(0xFF, 0xCC, 0x00), Inches(1.5)),
        ("LOW", "2", RGBColor(0x66, 0xBB, 0x6A), Inches(0.8)),
    ]
    for i, (sev, count, color, bar_w) in enumerate(severities):
        y = Inches(4.0 + i * 0.6)
        add_textbox(slide, Inches(0.9), y, Inches(1.2), Inches(0.35),
                    sev, font_size=12, color=color, bold=True)
        add_rect(slide, Inches(2.3), y + Inches(0.05), bar_w, Inches(0.25),
                 fill_color=color)
        add_textbox(slide, Inches(2.3) + bar_w + Inches(0.15), y, Inches(0.5), Inches(0.35),
                    count, font_size=12, color=COLOR_WHITE)

    # Recent activity
    add_card(slide, Inches(6.7), Inches(3.3), Inches(6.1), Inches(3.2))
    add_textbox(slide, Inches(7.0), Inches(3.45), Inches(5.5), Inches(0.35),
                "Recent Scan Activity", font_size=16, color=COLOR_GREEN, bold=True)

    activities = [
        ("\u2705  Scan #24 completed \u2014 3 critical findings", "2 min ago"),
        ("\U0001f527  AutoFix applied to XSS in /api/comments", "15 min ago"),
        ("\U0001f4cb  PDF Report generated for Scan #23", "1 hour ago"),
        ("\u26a0\ufe0f  New finding: SSRF in /api/proxy", "3 hours ago"),
        ("\u2705  Scan #22 completed \u2014 0 critical findings", "Yesterday"),
    ]
    for i, (activity, time) in enumerate(activities):
        y = Inches(4.0 + i * 0.48)
        add_textbox(slide, Inches(7.0), y, Inches(4.5), Inches(0.35),
                    activity, font_size=11, color=COLOR_WHITE)
        add_textbox(slide, Inches(11.5), y, Inches(1.3), Inches(0.35),
                    time, font_size=10, color=COLOR_MUTED, alignment=PP_ALIGN.RIGHT)

    add_footer_bar(slide)
    add_slide_number(slide, "7a")

    set_speaker_notes(slide, """[6:00 - 6:45] DEMO - DASHBOARD

"This is the BugBunny dashboard -- the command center for your security posture."

"Key metrics at a glance: total scans, active issues, fixes applied, and risk score."

"On the left, findings by severity -- only CONFIRMED findings. No noise."

"On the right, real-time activity feed. Scans completing, AutoFix being applied, reports generated."

"The frontend is React with TypeScript and TailwindCSS, with real-time updates via Supabase subscriptions."

Transition: "Let me show you how easy it is to trigger a scan..."
""")


def build_slide_7b(prs):
    """Demo: Scan Trigger."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "LIVE DEMO")

    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "Product Walkthrough: Scan Trigger", font_size=34, color=COLOR_GREEN, bold=True)
    add_textbox(slide, Inches(0.6), Inches(1.4), Inches(12), Inches(0.4),
                "One-click scanning with full pipeline orchestration",
                font_size=16, color=COLOR_MUTED)

    # Scan form
    add_card(slide, Inches(1.0), Inches(2.1), Inches(5.5), Inches(4.2))
    add_textbox(slide, Inches(1.3), Inches(2.3), Inches(5.0), Inches(0.4),
                "New Scan", font_size=20, color=COLOR_GREEN, bold=True)

    fields = [
        ("Repository URL", "github.com/acme/web-app"),
        ("Branch", "main"),
        ("Scan Profile", "Full Pipeline (SAST + DAST)"),
        ("Language", "Auto-detect (Python, JS, Java...)"),
    ]
    for i, (label, value) in enumerate(fields):
        y = Inches(2.9 + i * 0.7)
        add_textbox(slide, Inches(1.3), y, Inches(4.8), Inches(0.25),
                    label, font_size=11, color=COLOR_MUTED)
        add_rounded_rect(slide, Inches(1.3), y + Inches(0.25), Inches(4.8), Inches(0.35),
                         fill_color=RGBColor(0x1A, 0x1A, 0x1A), border_color=RGBColor(0x33, 0x33, 0x33))
        add_textbox(slide, Inches(1.5), y + Inches(0.25), Inches(4.4), Inches(0.35),
                    value, font_size=12, color=COLOR_WHITE)

    add_pill(slide, Inches(1.3), Inches(5.7), Inches(4.8), Inches(0.45),
             fill_color=COLOR_GREEN)
    add_textbox(slide, Inches(1.3), Inches(5.7), Inches(4.8), Inches(0.45),
                "\u25B6  Start Scan", font_size=16, color=COLOR_BLACK, bold=True,
                alignment=PP_ALIGN.CENTER)

    # Pipeline progress -- accurate to actual pipeline
    add_card(slide, Inches(7.0), Inches(2.1), Inches(5.8), Inches(4.2))
    add_textbox(slide, Inches(7.3), Inches(2.3), Inches(5.2), Inches(0.4),
                "Pipeline Progress", font_size=20, color=COLOR_GREEN, bold=True)

    pipeline_steps = [
        ("\u2705", "Repository cloned", "3s"),
        ("\u2705", "SAST scan (Semgrep)", "45s"),
        ("\u2705", "Context extraction complete", "12s"),
        ("\u2705", "AI triage (87 findings)", "90s"),
        ("\u23f3", "Targeted DAST running...", "~60s"),
        ("\u23f3", "Correlation engine", "pending"),
        ("\u2b55", "Report generation", "pending"),
    ]
    for i, (icon, step, time) in enumerate(pipeline_steps):
        y = Inches(2.9 + i * 0.48)
        is_active = icon == "\u23f3"
        text_color = COLOR_GREEN if icon == "\u2705" else (COLOR_WHITE if is_active else COLOR_MUTED)

        add_textbox(slide, Inches(7.3), y, Inches(0.4), Inches(0.35),
                    icon, font_size=14, color=text_color)
        add_textbox(slide, Inches(7.8), y, Inches(3.8), Inches(0.35),
                    step, font_size=13, color=text_color, bold=is_active)
        add_textbox(slide, Inches(11.6), y, Inches(1.0), Inches(0.35),
                    time, font_size=11, color=COLOR_MUTED, alignment=PP_ALIGN.RIGHT)

    # Progress bar
    add_rect(slide, Inches(7.3), Inches(6.0), Inches(5.2), Inches(0.12),
             fill_color=RGBColor(0x33, 0x33, 0x33))
    add_rect(slide, Inches(7.3), Inches(6.0), Inches(3.1), Inches(0.12),
             fill_color=COLOR_GREEN)

    add_footer_bar(slide)
    add_slide_number(slide, "7b")

    set_speaker_notes(slide, """[6:45 - 7:30] DEMO - SCAN TRIGGER

"Triggering a scan is simple. Enter your repo URL, select a branch, choose your scan profile, and hit Start."

"Full Pipeline mode runs SAST, AI triage, AND targeted DAST. Quick Scan runs just SAST + AI triage for speed."

"On the right, the pipeline executing in real-time. Each stage reports progress."

"Notice the timing: SAST scan 45 seconds, context extraction 12 seconds, AI triage 90 seconds for 87 findings. The full pipeline typically completes in under 5 minutes."

Transition: "Now let's look at the results..."
""")


def build_slide_7c(prs):
    """Demo: Results & Finding Cards."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "LIVE DEMO")

    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "Product Walkthrough: AI-Powered Results", font_size=34, color=COLOR_GREEN, bold=True)
    add_textbox(slide, Inches(0.6), Inches(1.4), Inches(12), Inches(0.4),
                "Every finding comes with AI reasoning, not just a severity label",
                font_size=16, color=COLOR_MUTED)

    # Finding card 1 -- Critical
    add_card(slide, Inches(0.6), Inches(2.0), Inches(6.0), Inches(2.2))
    add_rect(slide, Inches(0.6), Inches(2.0), Inches(0.08), Inches(2.2),
             fill_color=RGBColor(0xFF, 0x44, 0x44))

    add_textbox(slide, Inches(0.9), Inches(2.1), Inches(4.0), Inches(0.3),
                "SQL Injection \u2014 /api/users/search", font_size=15, color=COLOR_WHITE, bold=True)
    add_pill(slide, Inches(5.1), Inches(2.1), Inches(1.2), Inches(0.3),
             fill_color=RGBColor(0x44, 0x00, 0x00), border_color=RGBColor(0xFF, 0x44, 0x44))
    add_textbox(slide, Inches(5.1), Inches(2.1), Inches(1.2), Inches(0.3),
                "CRITICAL", font_size=10, color=RGBColor(0xFF, 0x44, 0x44), bold=True,
                alignment=PP_ALIGN.CENTER)

    card1_lines = [
        {"text": "AI Reasoning:", "size": 11, "color": COLOR_GREEN, "bold": True},
        {"text": "User input from request.args flows directly into SQL query", "size": 11, "color": COLOR_WHITE},
        {"text": "without parameterization. Endpoint is public, no auth required.", "size": 11, "color": COLOR_WHITE},
        {"text": "DAST confirmed: payload returned all records.", "size": 11, "color": RGBColor(0xFF, 0x79, 0x79)},
        {"text": "Confidence: 99% | SAST + AI + DAST verified", "size": 10, "color": COLOR_MUTED},
    ]
    add_multiline_textbox(slide, Inches(0.9), Inches(2.5), Inches(5.5), Inches(1.5), card1_lines)

    # Finding card 2 -- High
    add_card(slide, Inches(6.8), Inches(2.0), Inches(6.0), Inches(2.2))
    add_rect(slide, Inches(6.8), Inches(2.0), Inches(0.08), Inches(2.2),
             fill_color=RGBColor(0xFF, 0xAA, 0x00))

    add_textbox(slide, Inches(7.1), Inches(2.1), Inches(4.0), Inches(0.3),
                "XSS \u2014 /api/comments/render", font_size=15, color=COLOR_WHITE, bold=True)
    add_pill(slide, Inches(11.3), Inches(2.1), Inches(1.2), Inches(0.3),
             fill_color=RGBColor(0x44, 0x2A, 0x00), border_color=RGBColor(0xFF, 0xAA, 0x00))
    add_textbox(slide, Inches(11.3), Inches(2.1), Inches(1.2), Inches(0.3),
                "HIGH", font_size=10, color=RGBColor(0xFF, 0xAA, 0x00), bold=True,
                alignment=PP_ALIGN.CENTER)

    card2_lines = [
        {"text": "AI Reasoning:", "size": 11, "color": COLOR_GREEN, "bold": True},
        {"text": "Comment content rendered with innerHTML without DOMPurify", "size": 11, "color": COLOR_WHITE},
        {"text": "sanitization. Authenticated endpoint but any user can post.", "size": 11, "color": COLOR_WHITE},
        {"text": "DAST confirmed: script tag executed in response.", "size": 11, "color": RGBColor(0xFF, 0x79, 0x79)},
        {"text": "Confidence: 95% | SAST + AI + DAST verified", "size": 10, "color": COLOR_MUTED},
    ]
    add_multiline_textbox(slide, Inches(7.1), Inches(2.5), Inches(5.5), Inches(1.5), card2_lines)

    # Dismissed findings
    add_card(slide, Inches(0.6), Inches(4.5), Inches(12.2), Inches(1.5),
             border_color=RGBColor(0x33, 0x33, 0x33))
    add_textbox(slide, Inches(0.9), Inches(4.6), Inches(3.0), Inches(0.3),
                "Dismissed Findings (75 eliminated)", font_size=14, color=COLOR_MUTED, bold=True)

    dismissed_lines = [
        {"text": "\u274c  Hardcoded secret in test_config.py \u2014 AI: \"Test file, not deployed, no risk\"", "size": 12, "color": COLOR_MUTED},
        {"text": "\u274c  Path traversal in file_handler.py \u2014 AI: \"Input validated by middleware, os.path.realpath() applied\"", "size": 12, "color": COLOR_MUTED},
        {"text": "\u274c  SSRF in webhook.py \u2014 AI: \"URL allowlist enforced, only internal domains permitted\"", "size": 12, "color": COLOR_MUTED},
        {"text": "\u2026 and 72 more false positives eliminated with reasoning", "size": 12, "color": RGBColor(0x66, 0x66, 0x66)},
    ]
    add_multiline_textbox(slide, Inches(0.9), Inches(4.95), Inches(11.5), Inches(1.0), dismissed_lines)

    add_footer_bar(slide)
    add_slide_number(slide, "7c")

    set_speaker_notes(slide, """[7:30 - 8:15] DEMO - RESULTS

"Each finding card includes the AI's reasoning -- not just a severity label."

"SQL injection on the left: the AI explains WHY it's critical -- direct input flow, no sanitization, public endpoint. DAST confirmed it. 99% confidence."

"XSS on the right: similar depth. AI notes the endpoint is authenticated but any user can exploit it."

"The bottom section is equally important: 75 findings dismissed, each with reasoning. Hardcoded secret? It's in a test file. Path traversal? Middleware validates. This is the noise BugBunny eliminates."

Transition: "When we find a real vulnerability, BugBunny also fixes it..."
""")


def build_slide_7d(prs):
    """Demo: AutoFix & Report."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "LIVE DEMO")

    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "Product Walkthrough: AutoFix & Reports",
                font_size=34, color=COLOR_GREEN, bold=True)
    add_textbox(slide, Inches(0.6), Inches(1.4), Inches(12), Inches(0.4),
                "From detection to resolution in one click",
                font_size=16, color=COLOR_MUTED)

    # AutoFix section
    add_card(slide, Inches(0.6), Inches(2.0), Inches(6.0), Inches(4.3))
    add_textbox(slide, Inches(0.9), Inches(2.15), Inches(5.4), Inches(0.35),
                "\U0001f527 AI-Generated AutoFix", font_size=18, color=COLOR_GREEN, bold=True)

    fix_lines = [
        {"text": "Vulnerable Code:", "size": 12, "color": RGBColor(0xFF, 0x44, 0x44), "bold": True},
        {"text": "  query = f\"SELECT * FROM users", "size": 11, "color": RGBColor(0xFF, 0x79, 0x79)},
        {"text": "          WHERE name = '{name}'\"", "size": 11, "color": RGBColor(0xFF, 0x79, 0x79)},
        {"text": "  cursor.execute(query)", "size": 11, "color": RGBColor(0xFF, 0x79, 0x79)},
        {"text": "", "size": 8},
        {"text": "\u2193 AutoFix Applied \u2193", "size": 13, "color": COLOR_GREEN, "bold": True, "alignment": PP_ALIGN.CENTER},
        {"text": "", "size": 8},
        {"text": "Fixed Code:", "size": 12, "color": COLOR_GREEN, "bold": True},
        {"text": '  query = "SELECT * FROM users', "size": 11, "color": RGBColor(0x79, 0xFF, 0x79)},
        {"text": '          WHERE name = %s"', "size": 11, "color": RGBColor(0x79, 0xFF, 0x79)},
        {"text": "  cursor.execute(query, [name])", "size": 11, "color": RGBColor(0x79, 0xFF, 0x79)},
        {"text": "", "size": 8},
        {"text": "\u2705 Fix validated \u2014 re-scan confirms no vulnerability", "size": 12, "color": COLOR_GREEN},
        {"text": "\U0001f4ce Diff available for code review before merge", "size": 12, "color": COLOR_MUTED},
    ]
    add_multiline_textbox(slide, Inches(0.9), Inches(2.6), Inches(5.4), Inches(3.5), fix_lines)

    # Report section
    add_card(slide, Inches(6.9), Inches(2.0), Inches(5.9), Inches(4.3))
    add_textbox(slide, Inches(7.2), Inches(2.15), Inches(5.3), Inches(0.35),
                "\U0001f4cb PDF Compliance Report", font_size=18, color=COLOR_GREEN, bold=True)

    report_lines = [
        {"text": "BugBunny Security Scan Report", "size": 15, "color": COLOR_WHITE, "bold": True},
        {"text": "Generated: 2025-01-15 14:30 UTC", "size": 10, "color": COLOR_MUTED},
        {"text": "", "size": 6},
        {"text": "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501", "size": 8, "color": RGBColor(0x33, 0x33, 0x33)},
        {"text": "Executive Summary", "size": 14, "color": COLOR_GREEN, "bold": True},
        {"text": "  \u2022 Repository: acme/web-app (main)", "size": 11, "color": COLOR_WHITE},
        {"text": "  \u2022 87 SAST findings \u2192 12 confirmed", "size": 11, "color": COLOR_WHITE},
        {"text": "  \u2022 3 Critical | 5 High | 2 Medium | 2 Low", "size": 11, "color": COLOR_WHITE},
        {"text": "  \u2022 Risk Score: B+ (improving)", "size": 11, "color": COLOR_WHITE},
        {"text": "", "size": 6},
        {"text": "Detailed Findings with Evidence", "size": 14, "color": COLOR_GREEN, "bold": True},
        {"text": "  Each finding includes:", "size": 11, "color": COLOR_MUTED},
        {"text": "  \u2713 SAST source  \u2713 AI reasoning  \u2713 DAST proof", "size": 11, "color": COLOR_WHITE},
        {"text": "  \u2713 Code context  \u2713 Fix suggestion  \u2713 Priority", "size": 11, "color": COLOR_WHITE},
        {"text": "", "size": 6},
        {"text": "\U0001f4e5 Export: PDF | JSON | SARIF | CSV", "size": 12, "color": COLOR_GREEN},
    ]
    add_multiline_textbox(slide, Inches(7.2), Inches(2.6), Inches(5.3), Inches(3.5), report_lines)

    add_footer_bar(slide)
    add_slide_number(slide, "7d")

    set_speaker_notes(slide, """[8:15 - 9:00] DEMO - AUTOFIX & REPORTS

"BugBunny doesn't just find problems -- it fixes them. AutoFix uses AI to generate secure patches with built-in playbooks for common vulnerability types: SQL injection, XSS, command injection, SSRF, path traversal."

"In this example: SQL injection fixed by switching to parameterized queries. The fix is validated by re-scanning. The diff is available for code review before merging -- it can even create a GitHub PR automatically."

"On the right, our PDF compliance report built with ReportLab. Executive summary, risk scoring, detailed findings with the complete evidence chain. Each finding includes SAST source, AI reasoning, DAST proof, and fix suggestions."

"We export in PDF for compliance teams, JSON and SARIF for CI/CD integration, CSV for custom analysis."

Transition: "Let me show you how Pinecone powers our semantic intelligence..."
""")


def build_slide_8(prs):
    """Pinecone-Powered Semantic Intelligence."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "SEMANTIC INTELLIGENCE")

    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "Pinecone-Powered Semantic Intelligence",
                font_size=34, color=COLOR_GREEN, bold=True)
    add_textbox(slide, Inches(0.6), Inches(1.4), Inches(12), Inches(0.4),
                "Vector search enables deduplication, cross-project learning, and pattern memory",
                font_size=16, color=COLOR_MUTED)

    indexes = [
        {
            "name": "scanguard-bugs",
            "icon": "\U0001f50d",
            "desc": "Semantic Deduplication",
            "details": [
                "Embeds vulnerability descriptions",
                "Finds similar findings across scans",
                "Prevents duplicate alerts",
                "all-MiniLM-L6-v2 embeddings",
            ]
        },
        {
            "name": "scanguard-patterns",
            "icon": "\U0001f527",
            "desc": "Fix Knowledge Base",
            "details": [
                "Stores successful fix patterns",
                "Matches new findings to past fixes",
                "Improves AutoFix accuracy",
                "Cross-project fix reuse",
            ]
        },
        {
            "name": "scanguard-project-memory",
            "icon": "\U0001f4c1",
            "desc": "Project Memory",
            "details": [
                "Remembers project architecture",
                "Tracks resolved false positives",
                "Adapts to codebase patterns",
                "Reduces repeat false positives",
            ]
        },
    ]

    for i, idx in enumerate(indexes):
        x = Inches(0.6 + i * 4.1)
        y = Inches(2.1)
        w = Inches(3.8)

        add_card(slide, x, y, w, Inches(3.8))

        add_textbox(slide, x + Inches(0.2), y + Inches(0.15), w - Inches(0.4), Inches(0.4),
                    f'{idx["icon"]}  {idx["name"]}', font_size=14, color=COLOR_GREEN, bold=True)
        add_textbox(slide, x + Inches(0.2), y + Inches(0.55), w - Inches(0.4), Inches(0.35),
                    idx["desc"], font_size=16, color=COLOR_WHITE, bold=True)

        for j, detail in enumerate(idx["details"]):
            add_textbox(slide, x + Inches(0.3), y + Inches(1.1 + j * 0.5), w - Inches(0.5), Inches(0.45),
                        f"\u2022  {detail}", font_size=13, color=COLOR_MUTED)

    add_textbox(slide, Inches(0.6), Inches(6.15), Inches(12), Inches(0.35),
                "Flow:  New Finding \u2192 Embed (MiniLM) \u2192 Pinecone Search \u2192 Similar? Merge & Link  |  Novel? Store & Alert",
                font_size=13, color=COLOR_GREEN, alignment=PP_ALIGN.CENTER)

    add_footer_bar(slide)
    add_slide_number(slide, 8)

    set_speaker_notes(slide, """[9:00 - 9:45] SEMANTIC INTELLIGENCE

"BugBunny gets smarter with every scan, powered by Pinecone vector search."

"We maintain three indexes -- and these are the actual index names from our codebase:"

"scanguard-bugs: Every finding gets embedded using the all-MiniLM-L6-v2 sentence transformer model. When a new finding comes in, we search for semantically similar past findings and merge duplicates instead of creating noise."

"scanguard-patterns: Successful fix patterns are stored so we can suggest proven fixes for similar vulnerabilities, even across different projects."

"scanguard-project-memory: This remembers your project's architecture and tracks which findings you've resolved as false positives. Over time, BugBunny adapts to your specific codebase and generates fewer false positives."

Transition: "Let me show you the complete lifecycle..."
""")


def build_slide_9(prs):
    """Detection to Resolution in One Workflow."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "WORKFLOW")

    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "Detection to Resolution in One Workflow",
                font_size=34, color=COLOR_GREEN, bold=True)
    add_textbox(slide, Inches(0.6), Inches(1.4), Inches(12), Inches(0.4),
                "The complete security lifecycle \u2014 automated, intelligent, fast",
                font_size=16, color=COLOR_MUTED)

    lifecycle = [
        {"stage": "DETECT", "icon": "\U0001f50d", "time": "< 60s", "desc": "Semgrep SAST\nscans codebase"},
        {"stage": "UNDERSTAND", "icon": "\U0001f9e0", "time": "< 90s", "desc": "AI analyzes context\nand exploitability"},
        {"stage": "VERIFY", "icon": "\u2705", "time": "< 120s", "desc": "ZAP DAST proves\nexploitability"},
        {"stage": "FIX", "icon": "\U0001f527", "time": "< 30s", "desc": "AutoFix generates\nsecure patches"},
        {"stage": "REPORT", "icon": "\U0001f4cb", "time": "< 15s", "desc": "PDF/SARIF reports\nfor compliance"},
    ]

    stage_w = Inches(2.1)
    gap = Inches(0.35)
    total_w = len(lifecycle) * stage_w + (len(lifecycle) - 1) * gap
    start_x = (SLIDE_WIDTH - total_w) // 2

    for i, stage in enumerate(lifecycle):
        x = start_x + i * (stage_w + gap)
        y = Inches(2.3)

        add_card(slide, x, y, stage_w, Inches(2.8))

        add_textbox(slide, x, y + Inches(0.2), stage_w, Inches(0.5),
                    stage["icon"], font_size=32, color=COLOR_GREEN, alignment=PP_ALIGN.CENTER)

        add_textbox(slide, x + Inches(0.1), y + Inches(0.75), stage_w - Inches(0.2), Inches(0.35),
                    stage["stage"], font_size=18, color=COLOR_GREEN, bold=True,
                    alignment=PP_ALIGN.CENTER)

        add_textbox(slide, x + Inches(0.1), y + Inches(1.2), stage_w - Inches(0.2), Inches(0.7),
                    stage["desc"], font_size=13, color=COLOR_WHITE, alignment=PP_ALIGN.CENTER)

        add_pill(slide, x + Inches(0.4), y + Inches(2.2), stage_w - Inches(0.8), Inches(0.35),
                 fill_color=RGBColor(0x00, 0x33, 0x1A), border_color=COLOR_GREEN)
        add_textbox(slide, x + Inches(0.4), y + Inches(2.2), stage_w - Inches(0.8), Inches(0.35),
                    stage["time"], font_size=12, color=COLOR_GREEN, bold=True,
                    alignment=PP_ALIGN.CENTER)

        if i < len(lifecycle) - 1:
            add_textbox(slide, x + stage_w, y + Inches(1.0), gap, Inches(0.4),
                        "\u25B6", font_size=20, color=COLOR_GREEN, alignment=PP_ALIGN.CENTER)

    add_card(slide, Inches(3.5), Inches(5.5), Inches(6.3), Inches(1.1))
    add_textbox(slide, Inches(3.5), Inches(5.6), Inches(6.3), Inches(0.5),
                "Total: Under 5 Minutes", font_size=28, color=COLOR_GREEN, bold=True,
                alignment=PP_ALIGN.CENTER)
    add_textbox(slide, Inches(3.5), Inches(6.1), Inches(6.3), Inches(0.35),
                "From code commit to verified findings with fix suggestions and compliance report",
                font_size=13, color=COLOR_MUTED, alignment=PP_ALIGN.CENTER)

    add_footer_bar(slide)
    add_slide_number(slide, 9)

    set_speaker_notes(slide, """[9:45 - 10:30] COMPLETE LIFECYCLE

"Here's the complete BugBunny lifecycle in five stages."

"DETECT -- under 60 seconds. Semgrep scans your codebase with thousands of rules."
"UNDERSTAND -- under 90 seconds. AI analyzes every finding with full context."
"VERIFY -- under 2 minutes. ZAP DAST validates exploitability at runtime."
"FIX -- under 30 seconds. AutoFix generates secure patches with vulnerability-specific playbooks."
"REPORT -- under 15 seconds. PDF and SARIF reports for compliance teams."

"Total: under 5 minutes. From code to a verified, actionable security report. Compare that to Contrast Security's 2021 finding that teams spend 3+ hours investigating a SINGLE false positive."

Transition: "Let me show you the tech stack..."
""")


def build_slide_10(prs):
    """Built for Production, Not Just Demo."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "TECH STACK")

    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "Built for Production, Not Just Demo",
                font_size=34, color=COLOR_GREEN, bold=True)
    add_textbox(slide, Inches(0.6), Inches(1.4), Inches(12), Inches(0.4),
                "Production-grade architecture with modern cloud-native technologies",
                font_size=16, color=COLOR_MUTED)

    # 4-layer architecture -- accurate to actual codebase
    layers = [
        {
            "name": "Frontend",
            "color": COLOR_GREEN,
            "tech": "React + TypeScript + TailwindCSS",
            "features": "Real-time dashboard, Finding cards with AI reasoning, Interactive scan management",
        },
        {
            "name": "Backend API",
            "color": RGBColor(0x00, 0xBB, 0xFF),
            "tech": "FastAPI (Python) + Supabase Auth",
            "features": "REST API, JWT auth, Pipeline orchestration, WebSocket progress updates",
        },
        {
            "name": "Intelligence",
            "color": RGBColor(0xFF, 0xAA, 0x00),
            "tech": "LLM via OpenRouter + Pinecone + Semgrep + ZAP",
            "features": "AI triage, Vector search, SAST scanning, Targeted DAST, Context extraction",
        },
        {
            "name": "Infrastructure",
            "color": RGBColor(0xAA, 0x66, 0xFF),
            "tech": "Docker Compose + Supabase (PostgreSQL) + GitHub API",
            "features": "Containerized deployment, Real-time subscriptions, Git integration",
        },
    ]

    for i, layer in enumerate(layers):
        y = Inches(2.0 + i * 1.18)
        add_rounded_rect(slide, Inches(0.6), y, Inches(12.1), Inches(1.05),
                         fill_color=COLOR_CARD, border_color=layer["color"], border_width=1.5)

        add_pill(slide, Inches(0.9), y + Inches(0.15), Inches(1.8), Inches(0.32),
                 fill_color=layer["color"])
        add_textbox(slide, Inches(0.9), y + Inches(0.15), Inches(1.8), Inches(0.32),
                    layer["name"], font_size=12, color=COLOR_BLACK, bold=True,
                    alignment=PP_ALIGN.CENTER)

        add_textbox(slide, Inches(3.0), y + Inches(0.12), Inches(9.5), Inches(0.35),
                    layer["tech"], font_size=14, color=COLOR_WHITE, bold=True)

        add_textbox(slide, Inches(3.0), y + Inches(0.52), Inches(9.5), Inches(0.45),
                    layer["features"], font_size=12, color=COLOR_MUTED)

    badges = [
        "Docker Containerized", "Supabase Auth", "Real-time Updates",
        "Multi-language", "LLM-Agnostic", "SARIF Export"
    ]
    for i, badge in enumerate(badges):
        x = Inches(0.6 + i * 2.1)
        add_pill(slide, x, Inches(6.8), Inches(1.9), Inches(0.32),
                 fill_color=RGBColor(0x00, 0x33, 0x1A), border_color=COLOR_GREEN)
        add_textbox(slide, x, Inches(6.8), Inches(1.9), Inches(0.32),
                    badge, font_size=10, color=COLOR_GREEN, bold=True,
                    alignment=PP_ALIGN.CENTER)

    add_footer_bar(slide)
    add_slide_number(slide, 10)

    set_speaker_notes(slide, """[10:30 - 11:20] TECH STACK

"BugBunny is built for production."

"Frontend: React with TypeScript and TailwindCSS. Real-time dashboard via Supabase subscriptions."

"Backend: FastAPI with Supabase authentication. Pipeline orchestration with progress callbacks."

"Intelligence Layer: This is our core. LLM triage via OpenRouter -- which means we're model-agnostic and can swap between Gemini, Claude, GPT, or open-source models. Pinecone for semantic search. Semgrep for SAST. ZAP for DAST."

"Infrastructure: Docker Compose for one-command deployment. Supabase for PostgreSQL with real-time subscriptions. GitHub API for repository access."

"Key architectural decision: LLM-agnostic design via OpenRouter. We're not locked into any single AI provider."

Transition: "Let me show how this maps to the hackathon tracks..."
""")


def build_slide_11(prs):
    """Track Alignment."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "TRACK ALIGNMENT")

    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "Track Alignment", font_size=36, color=COLOR_GREEN, bold=True)
    add_textbox(slide, Inches(0.6), Inches(1.4), Inches(12), Inches(0.4),
                "BugBunny maps to Track 1 (AI Applications) and Track 4 (Security)",
                font_size=16, color=COLOR_MUTED)

    # Track 1
    add_card(slide, Inches(0.6), Inches(2.1), Inches(5.8), Inches(4.4))
    add_pill(slide, Inches(0.9), Inches(2.25), Inches(3.5), Inches(0.38),
             fill_color=COLOR_GREEN)
    add_textbox(slide, Inches(0.9), Inches(2.25), Inches(3.5), Inches(0.38),
                "Track 1: AI Applications (70%)", font_size=14, color=COLOR_BLACK, bold=True,
                alignment=PP_ALIGN.CENTER)

    track1_items = [
        ("\u2705", "AI-powered vulnerability triage via LLM"),
        ("\u2705", "Context-aware analysis with AST + data flow"),
        ("\u2705", "AI-generated fix suggestions (AutoFix)"),
        ("\u2705", "Semantic search via Pinecone embeddings"),
        ("\u2705", "Structured AI output (JSON reasoning)"),
        ("\u2705", "Progressive learning from project history"),
        ("\u2705", "LLM-agnostic architecture (OpenRouter)"),
    ]
    for i, (icon, text) in enumerate(track1_items):
        y = Inches(2.85 + i * 0.48)
        add_textbox(slide, Inches(1.0), y, Inches(0.4), Inches(0.35),
                    icon, font_size=14, color=COLOR_GREEN)
        add_textbox(slide, Inches(1.4), y, Inches(4.8), Inches(0.35),
                    text, font_size=13, color=COLOR_WHITE)

    # Track 4
    add_card(slide, Inches(6.7), Inches(2.1), Inches(6.1), Inches(4.4))
    add_pill(slide, Inches(7.0), Inches(2.25), Inches(3.5), Inches(0.38),
             fill_color=COLOR_GREEN)
    add_textbox(slide, Inches(7.0), Inches(2.25), Inches(3.5), Inches(0.38),
                "Track 4: Security (30%)", font_size=14, color=COLOR_BLACK, bold=True,
                alignment=PP_ALIGN.CENTER)

    track4_items = [
        ("\u2705", "SAST scanning (Semgrep, 3000+ rules)"),
        ("\u2705", "Targeted DAST validation (ZAP)"),
        ("\u2705", "OWASP Top 10 coverage"),
        ("\u2705", "Compliance reporting (PDF/SARIF)"),
        ("\u2705", "Reachability analysis"),
        ("\u2705", "Secure containerized execution"),
        ("\u2705", "Authentication & access control"),
    ]
    for i, (icon, text) in enumerate(track4_items):
        y = Inches(2.85 + i * 0.48)
        add_textbox(slide, Inches(7.1), y, Inches(0.4), Inches(0.35),
                    icon, font_size=14, color=COLOR_GREEN)
        add_textbox(slide, Inches(7.5), y, Inches(5.1), Inches(0.35),
                    text, font_size=13, color=COLOR_WHITE)

    add_footer_bar(slide)
    add_slide_number(slide, 11)

    set_speaker_notes(slide, """[11:20 - 12:05] TRACK ALIGNMENT

"Let me map BugBunny to the hackathon tracks."

"Track 1 -- AI Applications -- at about 70% of our innovation. AI-powered triage, context-aware analysis, AI-generated fixes, semantic search via Pinecone, structured output, and progressive learning. Importantly, we're LLM-agnostic via OpenRouter."

"Track 4 -- Security -- at 30%. Semgrep SAST with over 3,000 rules, targeted DAST with ZAP, OWASP Top 10 coverage, compliance reporting, reachability analysis, and secure containerized execution."

"Every green checkmark represents a feature that's implemented and working in our codebase."

Transition: "How does BugBunny compare to what's out there?"
""")


def build_slide_12(prs):
    """Why BugBunny Wins -- Competitive Comparison."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "COMPETITIVE EDGE")

    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "Why BugBunny Wins", font_size=36, color=COLOR_GREEN, bold=True)
    add_textbox(slide, Inches(0.6), Inches(1.4), Inches(12), Inches(0.4),
                "Feature comparison: BugBunny vs. existing tools",
                font_size=16, color=COLOR_MUTED)

    headers = ["Feature", "BugBunny", "Semgrep", "Snyk", "SonarQube", "LLM Wrappers"]
    col_widths = [Inches(2.8), Inches(1.8), Inches(1.6), Inches(1.6), Inches(1.8), Inches(2.1)]
    col_starts = [Inches(0.6)]
    for w in col_widths[:-1]:
        col_starts.append(col_starts[-1] + w + Inches(0.05))

    for i, (header, cw) in enumerate(zip(headers, col_widths)):
        x = col_starts[i]
        fill = COLOR_GREEN if i == 1 else RGBColor(0x1A, 0x1A, 0x1A)
        text_color = COLOR_BLACK if i == 1 else COLOR_GREEN
        add_rect(slide, x, Inches(1.95), cw, Inches(0.42), fill_color=fill)
        add_textbox(slide, x, Inches(1.95), cw, Inches(0.42),
                    header, font_size=12, color=text_color, bold=True,
                    alignment=PP_ALIGN.CENTER)

    # Rows -- honest comparison
    rows = [
        ("SAST Scanning", "\u2705", "\u2705", "\u2705", "\u2705", "\u274c"),
        ("AI Triage", "\u2705", "\u274c", "\u274c", "\u274c", "\u2705"),
        ("Context-Aware Analysis", "\u2705", "\u26a0\ufe0f", "\u26a0\ufe0f", "\u26a0\ufe0f", "\u26a0\ufe0f"),
        ("Targeted DAST", "\u2705", "\u274c", "\u274c", "\u274c", "\u274c"),
        ("Reachability Analysis", "\u2705", "\u26a0\ufe0f", "\u2705", "\u274c", "\u274c"),
        ("AI AutoFix", "\u2705", "\u274c", "\u2705", "\u274c", "\u26a0\ufe0f"),
        ("Semantic Dedup", "\u2705", "\u274c", "\u274c", "\u274c", "\u274c"),
        ("PDF Reports", "\u2705", "\u274c", "\u2705", "\u2705", "\u274c"),
        ("FP Rate (research)", "Up to 91%*", "70\u201390%*", "40\u201360%*", "50\u201370%*", "30\u201350%*"),
    ]

    for r, row_data in enumerate(rows):
        y = Inches(2.42 + r * 0.44)
        bg = COLOR_CARD if r % 2 == 0 else RGBColor(0x0A, 0x0A, 0x0A)

        for c, (val, cw) in enumerate(zip(row_data, col_widths)):
            x = col_starts[c]
            add_rect(slide, x, y, cw, Inches(0.42), fill_color=bg,
                     border_color=RGBColor(0x22, 0x22, 0x22), border_width=0.5)

            if c == 0:
                add_textbox(slide, x + Inches(0.1), y, cw - Inches(0.1), Inches(0.42),
                            val, font_size=11, color=COLOR_WHITE, bold=True)
            elif c == 1:
                add_textbox(slide, x, y, cw, Inches(0.42), val,
                            font_size=12, color=COLOR_GREEN, bold=True,
                            alignment=PP_ALIGN.CENTER)
            else:
                add_textbox(slide, x, y, cw, Inches(0.42), val,
                            font_size=12, color=COLOR_MUTED, alignment=PP_ALIGN.CENTER)

    # Footnote for FP rates
    add_textbox(slide, Inches(0.6), Inches(6.4), Inches(12), Inches(0.3),
                "*FP rates without AI triage, per Ghost Security 2025, NIST SP 500-326. BugBunny's pipeline aims to dramatically reduce this.",
                font_size=9, color=RGBColor(0x66, 0x66, 0x66))

    add_card(slide, Inches(2.0), Inches(6.7), Inches(9.3), Inches(0.35))
    add_textbox(slide, Inches(2.0), Inches(6.7), Inches(9.3), Inches(0.35),
                "BugBunny is the ONLY tool combining SAST + AI triage + targeted DAST + semantic dedup",
                font_size=13, color=COLOR_GREEN, bold=True, alignment=PP_ALIGN.CENTER)

    add_footer_bar(slide)
    add_slide_number(slide, 12)

    set_speaker_notes(slide, """[12:05 - 13:00] COMPETITIVE COMPARISON

"How does BugBunny compare to existing tools?"

"Semgrep: excellent SAST, but no AI triage, no DAST. Ghost Security's 2025 study showed up to 91% false positives on default rulesets."

"Snyk adds fix suggestions and reachability, but no AI triage, no DAST validation."

"SonarQube: great for code quality, limited security context. No AI, no DAST."

"LLM wrappers: They bolt AI on top of SAST, but without runtime validation, without semantic dedup, without the full pipeline."

"BugBunny uniquely combines SAST, AI triage, targeted DAST, reachability, AutoFix, semantic dedup, AND compliance reporting in one pipeline."

"Important note on the false positive row: those rates are from published research on tools with default configs, not vendor marketing numbers."

Transition: "Let me summarize the impact..."
""")


def build_slide_13(prs):
    """By the Numbers -- Impact metrics (honest framing)."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_section_label(slide, "IMPACT")

    add_textbox(slide, Inches(0.6), Inches(0.8), Inches(12), Inches(0.7),
                "By the Numbers", font_size=36, color=COLOR_GREEN, bold=True)
    add_textbox(slide, Inches(0.6), Inches(1.4), Inches(12), Inches(0.4),
                "Results from our demo pipeline scan",
                font_size=16, color=COLOR_MUTED)

    # 5 metric cards -- all honest
    metrics = [
        {"value": "86%", "label": "Noise\nRemoved", "sublabel": "75 of 87 findings eliminated"},
        {"value": "12", "label": "Confirmed\nVulnerabilities", "sublabel": "Each with AI reasoning"},
        {"value": "7", "label": "Pipeline\nStages", "sublabel": "SAST to report"},
        {"value": "< 5 min", "label": "End-to-End\nScan Time", "sublabel": "Full pipeline"},
        {"value": "3+ hrs", "label": "Per FP\nManual Review", "sublabel": "Contrast Security, 2021"},
    ]

    for i, metric in enumerate(metrics):
        x = Inches(0.4 + i * 2.55)
        y = Inches(2.1)
        w = Inches(2.35)
        h = Inches(3.5)

        add_card(slide, x, y, w, h)

        add_textbox(slide, x + Inches(0.1), y + Inches(0.4), w - Inches(0.2), Inches(1.0),
                    metric["value"], font_size=40, color=COLOR_GREEN, bold=True,
                    alignment=PP_ALIGN.CENTER)

        add_textbox(slide, x + Inches(0.1), y + Inches(1.5), w - Inches(0.2), Inches(0.8),
                    metric["label"], font_size=15, color=COLOR_WHITE, bold=True,
                    alignment=PP_ALIGN.CENTER)

        add_textbox(slide, x + Inches(0.1), y + Inches(2.7), w - Inches(0.2), Inches(0.45),
                    metric["sublabel"], font_size=11, color=COLOR_MUTED,
                    alignment=PP_ALIGN.CENTER)

    # Honest impact framing
    add_card(slide, Inches(1.0), Inches(5.9), Inches(11.3), Inches(0.9))
    add_multiline_textbox(slide, Inches(1.2), Inches(5.95), Inches(10.9), Inches(0.8), [
        {"text": "If Contrast Security's research holds (3+ hrs per false positive), eliminating 75 false positives",
         "size": 13, "color": COLOR_WHITE, "alignment": PP_ALIGN.CENTER},
        {"text": "saves 225+ hours of manual security review per scan cycle",
         "size": 15, "color": COLOR_GREEN, "bold": True, "alignment": PP_ALIGN.CENTER},
    ])

    add_footer_bar(slide)
    add_slide_number(slide, 13)

    set_speaker_notes(slide, """[13:00 - 13:45] IMPACT METRICS

"Let me walk through the numbers honestly."

"86% noise removed: In our demo pipeline scan, 75 of 87 SAST findings were eliminated as false positives with AI reasoning."

"12 confirmed vulnerabilities: Each with detailed AI analysis, severity assessment, and evidence chain."

"7 pipeline stages: From SAST scan to final report, each adding intelligence."

"Under 5 minutes end-to-end: For the full pipeline including DAST."

"And here's the industry context: Contrast Security's 2021 research found that 81% of teams spend 3 or more hours investigating a SINGLE false positive. If that holds, eliminating 75 false positives saves over 225 hours of manual review."

"We're not claiming made-up ROI numbers. We're showing you verifiable pipeline results combined with published industry research."

Transition: "Let me leave you with our vision..."
""")


def build_slide_14(prs):
    """Closing slide."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)

    add_rect(slide, Inches(0), Inches(0), SLIDE_WIDTH, Inches(0.04), fill_color=COLOR_GREEN)

    if os.path.exists(LOGO_PATH):
        slide.shapes.add_picture(LOGO_PATH, Inches(5.67), Inches(0.6), Inches(2), Inches(2))

    add_textbox(slide, Inches(1), Inches(2.8), Inches(11.333), Inches(0.8),
                "BugBunny", font_size=48, color=COLOR_GREEN, bold=True,
                alignment=PP_ALIGN.CENTER)
    add_textbox(slide, Inches(1), Inches(3.6), Inches(11.333), Inches(0.6),
                "Static Analysis That Actually Works",
                font_size=26, color=COLOR_WHITE, bold=True, alignment=PP_ALIGN.CENTER)

    add_textbox(slide, Inches(1), Inches(4.4), Inches(11.333), Inches(0.4),
                "What's Next", font_size=16, color=COLOR_GREEN, bold=True,
                alignment=PP_ALIGN.CENTER)

    roadmap_items = [
        "IDE plugins (VS Code, IntelliJ) for real-time scanning",
        "CI/CD pipeline integration (GitHub Actions, GitLab CI)",
        "Multi-repo organizational dashboards",
        "Custom rule engine for industry-specific compliance",
    ]
    for i, item in enumerate(roadmap_items):
        add_textbox(slide, Inches(3.0), Inches(4.8 + i * 0.35), Inches(7.3), Inches(0.33),
                    f"\u2192  {item}", font_size=13, color=COLOR_MUTED,
                    alignment=PP_ALIGN.LEFT)

    add_textbox(slide, Inches(1), Inches(6.3), Inches(11.333), Inches(0.5),
                "Team CSIS", font_size=24, color=COLOR_WHITE, bold=True,
                alignment=PP_ALIGN.CENTER)

    add_pill(slide, Inches(5.2), Inches(6.85), Inches(3.0), Inches(0.45),
             fill_color=COLOR_GREEN)
    add_textbox(slide, Inches(5.2), Inches(6.85), Inches(3.0), Inches(0.45),
                "Questions?", font_size=18, color=COLOR_BLACK, bold=True,
                alignment=PP_ALIGN.CENTER)

    add_footer_bar(slide)
    add_slide_number(slide, 14)

    set_speaker_notes(slide, """[13:45 - 15:00] CLOSING

"BugBunny: Static Analysis That Actually Works."

"We've shown you a platform that reduces SAST noise by 86% in our demo pipeline, combines AI triage with runtime verification -- something no other tool does -- and delivers results in under 5 minutes."

"Our roadmap includes IDE plugins for real-time scanning, CI/CD integration, organizational dashboards, and custom compliance rules."

"We're Team CSIS. We built BugBunny because security tools should help developers, not drown them in noise."

"Thank you. We'd love your questions."

[Be ready for questions about:]
- AI model choice: We use OpenRouter (currently Gemini Flash) -- model-agnostic by design
- The 87-to-12 demo data: Transparent about it being our demo pipeline result
- ZAP DAST safety: Runs in Docker containers, isolated environment
- Pinecone scaling: Three indexes, sentence-transformer embeddings
- Language support: Semgrep covers 30+ languages
- Why not just use Snyk/Semgrep Pro? We add AI triage + DAST + semantic dedup layer
""")


# =============================================================================
# MAIN
# =============================================================================

def main():
    prs = Presentation()
    prs.slide_width = SLIDE_WIDTH
    prs.slide_height = SLIDE_HEIGHT

    print("Building BugBunny Hackathon Presentation...")
    print("=" * 50)

    builders = [
        ("Slide 1: Hook", build_slide_1),
        ("Slide 2: The False Positive Tax", build_slide_2),
        ("Slide 3: 87 to 12", build_slide_3),
        ("Slide 4: Intelligence Pipeline", build_slide_4),
        ("Slide 5: Targeted DAST", build_slide_5),
        ("Slide 6: AI Triage Engine", build_slide_6),
        ("Slide 7a: Demo - Dashboard", build_slide_7a),
        ("Slide 7b: Demo - Scan Trigger", build_slide_7b),
        ("Slide 7c: Demo - Results", build_slide_7c),
        ("Slide 7d: Demo - AutoFix & Reports", build_slide_7d),
        ("Slide 8: Semantic Intelligence", build_slide_8),
        ("Slide 9: Complete Lifecycle", build_slide_9),
        ("Slide 10: Tech Stack", build_slide_10),
        ("Slide 11: Track Alignment", build_slide_11),
        ("Slide 12: Competitive Comparison", build_slide_12),
        ("Slide 13: Impact Metrics", build_slide_13),
        ("Slide 14: Closing", build_slide_14),
    ]

    for name, builder in builders:
        print(f"  Building {name}...")
        builder(prs)

    print("=" * 50)
    print(f"Saving to: {OUTPUT_FILE}")
    prs.save(OUTPUT_FILE)
    print(f"Done! {len(prs.slides)} slides generated.")
    print(f"\nPresentation saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
