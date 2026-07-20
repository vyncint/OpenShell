// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy proposal inbox for the sandbox screen.

use crate::app::App;
use openshell_core::proto::{L7Allow, L7DenyRule, L7QueryMatcher, NetworkEndpoint, PolicyChunk};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap};

use super::centered_rect;

/// Draw the policy proposal inbox (list view with highlight bar).
pub fn draw(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let t = &app.theme;
    let pending_count = app
        .draft_chunks
        .iter()
        .filter(|c| c.status == "pending")
        .count();

    let title = if pending_count > 0 {
        Line::from(vec![
            Span::styled(" Policy Proposal Inbox ", t.heading),
            Span::styled(format!(" {pending_count} pending "), t.badge),
            Span::raw(" "),
        ])
    } else {
        Line::from(Span::styled(" Policy Proposal Inbox ", t.heading))
    };

    let mut block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(t.border_focused)
        .padding(Padding::horizontal(1));

    if app.sandbox_policy_is_global {
        block = block.title_bottom(
            Line::from(Span::styled(
                " Cannot approve rules while global policy is active ",
                t.status_warn,
            ))
            .left_aligned(),
        );
    }

    if app.draft_chunks.is_empty() {
        let msg = Paragraph::new(
            "No policy proposals yet. Denied connections or sandboxed agents can create \
             proposals for review.",
        )
        .block(block)
        .style(t.muted);
        frame.render_widget(msg, area);
        return;
    }

    // Calculate visible area inside the block (borders + padding).
    let inner_height = area.height.saturating_sub(2) as usize;
    app.draft_viewport_height = inner_height;

    // Clamp cursor to visible range.
    let total = app.draft_chunks.len();
    let visible_count = total.saturating_sub(app.draft_scroll).min(inner_height);
    if visible_count > 0 {
        app.draft_selected = app.draft_selected.min(visible_count - 1);
    }

    let cursor_pos = app.draft_selected;

    let lines: Vec<Line<'_>> = app
        .draft_chunks
        .iter()
        .skip(app.draft_scroll)
        .take(inner_height)
        .enumerate()
        .map(|(i, chunk)| {
            let is_selected = i == cursor_pos;

            let globally_locked = app.sandbox_policy_is_global;

            let status_style = if globally_locked {
                t.muted
            } else {
                match chunk.status.as_str() {
                    "pending" => t.status_warn,
                    "approved" => t.status_ok,
                    "rejected" => t.status_err,
                    _ => t.muted,
                }
            };

            let name_style = if globally_locked {
                t.muted
            } else if is_selected {
                t.selected
            } else if chunk.status == "rejected" {
                t.muted
            } else {
                t.text
            };

            let mut spans = Vec::new();

            // Highlight bar prefix (like logs).
            if is_selected {
                spans.push(Span::styled("▌ ", t.accent));
            } else {
                spans.push(Span::raw("  "));
            }

            // Endpoint summary with L4/L7 detail.
            let endpoint_str = chunk
                .proposed_rule
                .as_ref()
                .and_then(|r| r.endpoints.first())
                .map(format_endpoint_summary)
                .unwrap_or_default();

            spans.push(Span::styled(proposal_headline(chunk), name_style));

            spans.push(Span::raw("  "));
            spans.push(Span::styled(format!("[{}]", chunk.status), status_style));

            if let Some(validation) = validation_badge(chunk) {
                let validation_style = match validation.kind {
                    ValidationBadgeKind::Clear => t.status_ok,
                    ValidationBadgeKind::Review => t.status_warn,
                };
                spans.push(Span::styled("  ", t.muted));
                spans.push(Span::styled(
                    format!("[{}]", validation.short_label),
                    validation_style,
                ));
            }

            if let Some(warning) = proposal_scope_warning(chunk) {
                spans.push(Span::styled("  ", t.muted));
                spans.push(Span::styled(
                    format!("[{}]", warning.short_label()),
                    t.status_warn.add_modifier(Modifier::BOLD),
                ));
            }

            if !endpoint_str.is_empty() {
                spans.push(Span::styled("  ", t.muted));
                spans.push(Span::styled(endpoint_str, t.accent));
            }
            // Show binary name (just the filename, not full path) if present.
            if !chunk.binary.is_empty() {
                let bin_short = chunk.binary.rsplit('/').next().unwrap_or(&chunk.binary);
                spans.push(Span::styled("  ", t.muted));
                spans.push(Span::styled(format!("({bin_short})"), t.muted));
            }
            spans.push(Span::styled(
                format!("  {:.0}%", chunk.confidence * 100.0),
                t.muted,
            ));
            if chunk.hit_count > 1 {
                spans.push(Span::styled(format!("  {}x", chunk.hit_count), t.accent));
            }
            if let Some(intent) = agent_intent(chunk) {
                spans.push(Span::styled("  Agent intent: ", t.muted));
                spans.push(Span::styled(intent, name_style));
            }

            let mut line = Line::from(spans);
            if is_selected {
                line = line.style(t.log_cursor);
            }
            line
        })
        .collect();

    // Scroll position indicator.
    let pos = app.draft_scroll + cursor_pos + 1;
    let scroll_info = format!(" [{pos}/{total}] ");

    let block = block.title_bottom(Line::from(vec![Span::styled(scroll_info, t.muted)]));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

// ---------------------------------------------------------------------------
// Detail popup (Enter key)
// ---------------------------------------------------------------------------

pub fn draw_detail_popup(
    frame: &mut Frame<'_>,
    chunk: &PolicyChunk,
    area: Rect,
    theme: &crate::theme::Theme,
) {
    let t = theme;
    let popup_width = (area.width * 4 / 5).min(area.width.saturating_sub(4));
    let popup_height = 26u16.min(area.height.saturating_sub(4));
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let status_style = match chunk.status.as_str() {
        "pending" => t.status_warn.add_modifier(Modifier::BOLD),
        "approved" => t.status_ok.add_modifier(Modifier::BOLD),
        "rejected" => t.status_err.add_modifier(Modifier::BOLD),
        _ => t.muted,
    };

    let block = Block::default()
        .title(Span::styled(
            format!(" {} ", proposal_headline(chunk)),
            t.heading,
        ))
        .borders(Borders::ALL)
        .border_style(t.accent)
        .padding(Padding::new(1, 1, 0, 0));

    let mut lines: Vec<Line<'_>> = vec![
        Line::from(vec![
            Span::styled("Status:     ", t.muted),
            Span::styled(&chunk.status, status_style),
        ]),
        Line::from(vec![
            Span::styled("Confidence: ", t.muted),
            Span::styled(format!("{:.0}%", chunk.confidence * 100.0), t.text),
        ]),
    ];

    if let Some(validation) = validation_badge(chunk) {
        let validation_style = match validation.kind {
            ValidationBadgeKind::Clear => t.status_ok.add_modifier(Modifier::BOLD),
            ValidationBadgeKind::Review => t.status_warn.add_modifier(Modifier::BOLD),
        };
        let mut validation_lines = validation.detail_label.lines();
        if let Some(first) = validation_lines.next() {
            lines.push(Line::from(vec![
                Span::styled("Validation: ", t.muted),
                Span::styled(first, validation_style),
            ]));
        }
        for line in validation_lines {
            lines.push(Line::from(vec![
                Span::raw("            "),
                Span::styled(line, validation_style),
            ]));
        }
    }

    if let Some(warning) = proposal_scope_warning(chunk) {
        lines.push(Line::from(vec![
            Span::styled("Scope:      ", t.muted),
            Span::styled(
                warning.detail_label(),
                t.status_warn.add_modifier(Modifier::BOLD),
            ),
        ]));
    }

    if let Some(intent) = agent_intent(chunk) {
        lines.push(Line::from(vec![
            Span::styled("Agent intent: ", t.muted),
            Span::styled(intent, t.text),
        ]));
    }

    if let Some(guidance) = rejection_guidance(chunk) {
        lines.push(Line::from(vec![
            Span::styled("Reviewer guidance: ", t.muted),
            Span::styled(guidance, t.status_err.add_modifier(Modifier::BOLD)),
        ]));
    }

    // Binary (denormalized from the denial).
    if !chunk.binary.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Binary:     ", t.muted),
            Span::styled(&chunk.binary, t.text),
        ]));
    }

    // Hit count (accumulated real denial count) and first/last seen.
    lines.push(Line::from(vec![
        Span::styled("Denied:     ", t.muted),
        Span::styled(
            format!(
                "{} connection{}",
                chunk.hit_count,
                if chunk.hit_count == 1 { "" } else { "s" }
            ),
            t.accent,
        ),
        Span::styled(
            format!(
                "  (first {} / last {})",
                format_short_time(chunk.first_seen_ms),
                format_short_time(chunk.last_seen_ms),
            ),
            t.muted,
        ),
    ]));

    // Endpoints.
    if let Some(ref rule) = chunk.proposed_rule {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Endpoints:", t.muted)));
        for ep in &rule.endpoints {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("-> ", t.muted),
                Span::styled(format_endpoint_summary(ep), t.accent),
            ]));

            for detail in format_endpoint_details(ep) {
                lines.push(Line::from(vec![
                    Span::raw("     "),
                    Span::styled(detail, t.text),
                ]));
            }
        }

        // Binaries.
        if !rule.binaries.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Binaries:", t.muted)));
            for b in &rule.binaries {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(&b.path, t.text),
                ]));
            }
        }
    }

    // Security notes.
    if !chunk.security_notes.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            format!("! {}", chunk.security_notes),
            t.status_warn.add_modifier(Modifier::BOLD),
        )]));
    }

    // Action hints — state-aware toggle keys.
    lines.push(Line::from(""));
    let mut hint_spans: Vec<Span<'_>> = Vec::new();
    match chunk.status.as_str() {
        "pending" => {
            hint_spans.extend([
                Span::styled("[a]", t.key_hint),
                Span::styled(" Approve  ", t.text),
                Span::styled("[x]", t.key_hint),
                Span::styled(" Reject  ", t.text),
            ]);
        }
        "approved" => {
            hint_spans.extend([
                Span::styled("[x]", t.key_hint),
                Span::styled(" Revoke  ", t.text),
            ]);
        }
        "rejected" => {
            hint_spans.extend([
                Span::styled("[a]", t.key_hint),
                Span::styled(" Approve  ", t.text),
            ]);
        }
        _ => {}
    }
    hint_spans.extend([
        Span::styled("[Esc]", t.muted),
        Span::styled(" Close", t.muted),
    ]);
    lines.push(Line::from(hint_spans));

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup_area,
    );
}

// ---------------------------------------------------------------------------
// Approve-all confirmation popup ([A] key)
// ---------------------------------------------------------------------------

pub fn draw_approve_all_popup(
    frame: &mut Frame<'_>,
    chunks: &[PolicyChunk],
    area: Rect,
    theme: &crate::theme::Theme,
) {
    let t = theme;
    let count = chunks.len();
    // Height: header(1) + blank(1) + chunks(count, capped at 12) + blank(1) + hints(1) + borders(2) + padding(1)
    let list_lines = count.min(12);
    let popup_height = u16::try_from(7 + list_lines).unwrap_or(u16::MAX);
    let popup_height = popup_height.min(area.height.saturating_sub(4));
    let popup_width = (area.width * 4 / 5).min(area.width.saturating_sub(4));
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(
            " Approve All ",
            t.status_warn.add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(t.accent)
        .padding(Padding::new(1, 1, 0, 0));

    // Usable width inside borders + padding.
    let inner_width = popup_width.saturating_sub(4) as usize;

    let mut lines: Vec<Line<'_>> = Vec::new();

    lines.push(Line::from(vec![
        Span::styled("Approve ", t.text),
        Span::styled(
            format!("{count}"),
            t.status_warn.add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                " pending policy request{}?",
                if count == 1 { "" } else { "s" }
            ),
            t.text,
        ),
    ]));
    lines.push(Line::from(""));

    for (i, chunk) in chunks.iter().enumerate() {
        if i >= 12 {
            lines.push(Line::from(Span::styled(
                format!("  ... and {} more", count - 12),
                t.muted,
            )));
            break;
        }
        let endpoint_str = chunk
            .proposed_rule
            .as_ref()
            .and_then(|r| r.endpoints.first())
            .map(format_endpoint_summary)
            .unwrap_or_default();

        // Truncate to fit within the popup width.
        // "  -> " (5) + rule_name + "  " (2) + endpoint
        let prefix_len = 5;
        let sep_len = 2;
        let budget = inner_width.saturating_sub(prefix_len + sep_len);
        let headline = proposal_headline(chunk);
        let (name_str, ep_str) = if headline.len() + endpoint_str.len() > budget {
            let ep_budget = endpoint_str.len().min(budget / 2);
            let name_budget = budget.saturating_sub(ep_budget);
            (
                truncate_str(headline, name_budget),
                truncate_str(&endpoint_str, ep_budget),
            )
        } else {
            (headline.to_string(), endpoint_str)
        };

        let mut row_spans = vec![
            Span::styled("  -> ", t.muted),
            Span::styled(name_str, t.text),
            Span::styled("  ", t.muted),
            Span::styled(ep_str, t.accent),
        ];
        if !chunk.binary.is_empty() {
            let bin_short = chunk.binary.rsplit('/').next().unwrap_or(&chunk.binary);
            row_spans.push(Span::styled("  ", t.muted));
            row_spans.push(Span::styled(format!("({bin_short})"), t.muted));
        }
        lines.push(Line::from(row_spans));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("[y/Enter]", t.key_hint),
        Span::styled(" Approve all  ", t.text),
        Span::styled("[n/Esc]", t.key_hint),
        Span::styled(" Cancel", t.text),
    ]));

    frame.render_widget(Paragraph::new(lines).block(block), popup_area);
}

/// Truncate a string to `max_len` chars, appending "..." if truncated.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s.chars().take(max_len).collect()
    } else {
        let mut out: String = s.chars().take(max_len - 3).collect();
        out.push_str("...");
        out
    }
}

const UNNAMED_PROPOSAL: &str = "Unnamed policy proposal";

fn proposal_headline(chunk: &PolicyChunk) -> &str {
    let headline = chunk.rule_name.trim();
    if headline.is_empty() {
        UNNAMED_PROPOSAL
    } else {
        headline
    }
}

fn agent_intent(chunk: &PolicyChunk) -> Option<&str> {
    non_empty_trimmed(&chunk.rationale)
}

fn rejection_guidance(chunk: &PolicyChunk) -> Option<&str> {
    if chunk.status != "rejected" {
        return None;
    }
    non_empty_trimmed(&chunk.rejection_reason)
}

fn non_empty_trimmed(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValidationBadgeKind {
    Clear,
    Review,
}

struct ValidationBadge<'a> {
    kind: ValidationBadgeKind,
    short_label: &'static str,
    detail_label: &'a str,
}

fn validation_badge(chunk: &PolicyChunk) -> Option<ValidationBadge<'_>> {
    let validation = chunk.validation_result.trim();
    if validation.is_empty() {
        return None;
    }

    let (kind, short_label) = if validation == "prover: no new findings" {
        (ValidationBadgeKind::Clear, "validation: clear")
    } else {
        (ValidationBadgeKind::Review, "validation: review")
    };

    Some(ValidationBadge {
        kind,
        short_label,
        detail_label: validation,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScopeWarning {
    L4Only,
    RestWithoutMethodPath,
}

impl ScopeWarning {
    fn short_label(self) -> &'static str {
        match self {
            Self::L4Only => "broad L4",
            Self::RestWithoutMethodPath => "broad REST",
        }
    }

    fn detail_label(self) -> &'static str {
        match self {
            Self::L4Only => "Broad L4 access has no HTTP method or path enforcement.",
            Self::RestWithoutMethodPath => {
                "Broad REST access lacks an explicit method and path on every allow rule."
            }
        }
    }
}

fn proposal_scope_warning(chunk: &PolicyChunk) -> Option<ScopeWarning> {
    let mut warning = None;
    let endpoints = chunk.proposed_rule.as_ref()?.endpoints.iter();
    for endpoint in endpoints {
        match endpoint_scope_warning(endpoint) {
            Some(ScopeWarning::L4Only) => return Some(ScopeWarning::L4Only),
            Some(rest_warning) => warning = Some(rest_warning),
            None => {}
        }
    }
    warning
}

fn endpoint_scope_warning(endpoint: &NetworkEndpoint) -> Option<ScopeWarning> {
    let protocol = endpoint.protocol.trim();
    if protocol.is_empty() {
        return Some(ScopeWarning::L4Only);
    }
    if !protocol.eq_ignore_ascii_case("rest") {
        return None;
    }

    let has_narrow_method_path = !endpoint.rules.is_empty()
        && endpoint.rules.iter().all(|rule| {
            rule.allow.as_ref().is_some_and(|allow| {
                is_narrow_scope_component(&allow.method) && is_narrow_scope_component(&allow.path)
            })
        });
    (!has_narrow_method_path).then_some(ScopeWarning::RestWithoutMethodPath)
}

fn is_narrow_scope_component(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && value != "*" && value != "**" && value != "/**"
}

fn format_endpoint_summary(endpoint: &NetworkEndpoint) -> String {
    let host_port = if endpoint.port > 0 {
        format!("{}:{}", endpoint.host, endpoint.port)
    } else {
        endpoint.host.clone()
    };

    let mut tags = vec![endpoint_layer_label(endpoint).to_string()];
    if !endpoint.access.is_empty() {
        tags.push(format!("access={}", endpoint.access));
    }
    for rule in &endpoint.rules {
        if let Some(allow) = &rule.allow {
            tags.push(format!("allow {}", format_allow_rule(allow)));
        }
    }
    for deny in &endpoint.deny_rules {
        tags.push(format!("deny {}", format_deny_rule(deny)));
    }

    format!("{host_port} [{}]", tags.join(", "))
}

fn format_endpoint_details(endpoint: &NetworkEndpoint) -> Vec<String> {
    let mut details = Vec::new();

    if !endpoint.path.is_empty() {
        details.push(format!("Path scope: {}", endpoint.path));
    }
    if !endpoint.tls.is_empty() {
        details.push(format!("TLS: {}", endpoint.tls));
    }
    if !endpoint.enforcement.is_empty() {
        details.push(format!("Enforcement: {}", endpoint.enforcement));
    }
    if endpoint.request_body_credential_rewrite {
        details.push("Request body credential rewrite".to_string());
    }
    if endpoint.websocket_credential_rewrite {
        details.push("WebSocket credential rewrite".to_string());
    }
    for rule in &endpoint.rules {
        if let Some(allow) = &rule.allow {
            details.push(format!("Allow: {}", format_allow_rule(allow)));
        }
    }
    for deny in &endpoint.deny_rules {
        details.push(format!("Deny: {}", format_deny_rule(deny)));
    }

    details
}

fn endpoint_layer_label(endpoint: &NetworkEndpoint) -> &str {
    if endpoint.protocol.eq_ignore_ascii_case("rest") {
        "L7 rest"
    } else if endpoint.protocol.is_empty() {
        "L4"
    } else {
        endpoint.protocol.as_str()
    }
}

fn format_allow_rule(allow: &L7Allow) -> String {
    let mut parts = Vec::new();
    if !allow.method.is_empty() || !allow.path.is_empty() {
        parts.push(format!(
            "{} {}",
            non_empty_or(&allow.method, "*"),
            non_empty_or(&allow.path, "*")
        ));
    }
    if !allow.command.is_empty() {
        parts.push(format!("command {}", allow.command));
    }
    if !allow.operation_type.is_empty() || !allow.operation_name.is_empty() {
        parts.push(format!(
            "graphql {} {}",
            non_empty_or(&allow.operation_type, "*"),
            non_empty_or(&allow.operation_name, "*")
        ));
    }
    if !allow.fields.is_empty() {
        parts.push(format!("fields {}", allow.fields.join(",")));
    }
    append_query_matchers(&mut parts, &allow.query);
    if parts.is_empty() {
        "*".to_string()
    } else {
        parts.join("; ")
    }
}

fn format_deny_rule(deny: &L7DenyRule) -> String {
    let mut parts = Vec::new();
    if !deny.method.is_empty() || !deny.path.is_empty() {
        parts.push(format!(
            "{} {}",
            non_empty_or(&deny.method, "*"),
            non_empty_or(&deny.path, "*")
        ));
    }
    if !deny.command.is_empty() {
        parts.push(format!("command {}", deny.command));
    }
    if !deny.operation_type.is_empty() || !deny.operation_name.is_empty() {
        parts.push(format!(
            "graphql {} {}",
            non_empty_or(&deny.operation_type, "*"),
            non_empty_or(&deny.operation_name, "*")
        ));
    }
    if !deny.fields.is_empty() {
        parts.push(format!("fields {}", deny.fields.join(",")));
    }
    append_query_matchers(&mut parts, &deny.query);
    if parts.is_empty() {
        "*".to_string()
    } else {
        parts.join("; ")
    }
}

fn append_query_matchers(
    parts: &mut Vec<String>,
    query: &std::collections::HashMap<String, L7QueryMatcher>,
) {
    if query.is_empty() {
        return;
    }
    let mut entries: Vec<_> = query.iter().collect();
    entries.sort_by_key(|(key, _)| *key);
    let formatted = entries
        .into_iter()
        .map(|(key, matcher)| {
            if matcher.any.is_empty() {
                format!("{key}={}", non_empty_or(&matcher.glob, "*"))
            } else {
                format!("{key} in [{}]", matcher.any.join(","))
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    parts.push(format!("query {formatted}"));
}

fn non_empty_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}

fn format_short_time(epoch_ms: i64) -> String {
    if epoch_ms <= 0 {
        return String::from("--:--:--");
    }
    let secs = epoch_ms / 1000;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{L7Rule, NetworkPolicyRule};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn chunk_with_endpoint(endpoint: NetworkEndpoint) -> PolicyChunk {
        PolicyChunk {
            proposed_rule: Some(NetworkPolicyRule {
                endpoints: vec![endpoint],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn rest_endpoint(method: &str, path: &str) -> NetworkEndpoint {
        NetworkEndpoint {
            protocol: "rest".to_string(),
            rules: vec![L7Rule {
                allow: Some(L7Allow {
                    method: method.to_string(),
                    path: path.to_string(),
                    ..Default::default()
                }),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn proposal_headline_uses_trimmed_rule_name_and_fallback() {
        let named = PolicyChunk {
            rule_name: "  github contents write  ".to_string(),
            ..Default::default()
        };
        assert_eq!(proposal_headline(&named), "github contents write");

        assert_eq!(proposal_headline(&PolicyChunk::default()), UNNAMED_PROPOSAL);
    }

    #[test]
    fn agent_intent_uses_trimmed_rationale() {
        let chunk = PolicyChunk {
            rationale: "  update one documentation file  ".to_string(),
            ..Default::default()
        };
        assert_eq!(agent_intent(&chunk), Some("update one documentation file"));
        assert_eq!(agent_intent(&PolicyChunk::default()), None);
    }

    #[test]
    fn validation_badge_distinguishes_clear_and_review_results() {
        let clear = PolicyChunk {
            validation_result: "prover: no new findings".to_string(),
            ..Default::default()
        };
        let badge = validation_badge(&clear).expect("validation badge");
        assert_eq!(badge.kind, ValidationBadgeKind::Clear);
        assert_eq!(badge.short_label, "validation: clear");

        let findings = PolicyChunk {
            validation_result: "prover: findings\ncapability_expansion: PUT".to_string(),
            ..Default::default()
        };
        let badge = validation_badge(&findings).expect("validation badge");
        assert_eq!(badge.kind, ValidationBadgeKind::Review);
        assert_eq!(badge.detail_label, findings.validation_result);

        assert!(validation_badge(&PolicyChunk::default()).is_none());
    }

    #[test]
    fn rejection_guidance_only_surfaces_for_rejected_chunks() {
        let mut chunk = PolicyChunk {
            status: "pending".to_string(),
            rejection_reason: "  scope to docs paths  ".to_string(),
            ..Default::default()
        };
        assert_eq!(rejection_guidance(&chunk), None);

        chunk.status = "rejected".to_string();
        assert_eq!(rejection_guidance(&chunk), Some("scope to docs paths"));

        chunk.rejection_reason.clear();
        assert_eq!(rejection_guidance(&chunk), None);
    }

    #[test]
    fn scope_warning_flags_l4_and_unscoped_rest_endpoints() {
        assert_eq!(
            endpoint_scope_warning(&NetworkEndpoint::default()),
            Some(ScopeWarning::L4Only)
        );

        let rest = NetworkEndpoint {
            protocol: "rest".to_string(),
            ..Default::default()
        };
        assert_eq!(
            endpoint_scope_warning(&rest),
            Some(ScopeWarning::RestWithoutMethodPath)
        );
        assert_eq!(
            endpoint_scope_warning(&rest_endpoint("PUT", "")),
            Some(ScopeWarning::RestWithoutMethodPath)
        );
        assert_eq!(
            endpoint_scope_warning(&rest_endpoint("*", "/repos/org/repo/**")),
            Some(ScopeWarning::RestWithoutMethodPath)
        );
        assert_eq!(
            endpoint_scope_warning(&rest_endpoint("GET", "/**")),
            Some(ScopeWarning::RestWithoutMethodPath)
        );
    }

    #[test]
    fn scope_warning_accepts_explicit_rest_method_and_path() {
        assert_eq!(
            endpoint_scope_warning(&rest_endpoint("PUT", "/repos/org/repo/contents/docs/**")),
            None
        );

        let graphql = NetworkEndpoint {
            protocol: "graphql".to_string(),
            ..Default::default()
        };
        assert_eq!(endpoint_scope_warning(&graphql), None);
    }

    #[test]
    fn proposal_scope_warning_prioritizes_l4_access() {
        let chunk = PolicyChunk {
            proposed_rule: Some(NetworkPolicyRule {
                endpoints: vec![rest_endpoint("PUT", ""), NetworkEndpoint::default()],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(proposal_scope_warning(&chunk), Some(ScopeWarning::L4Only));

        assert_eq!(
            proposal_scope_warning(&chunk_with_endpoint(rest_endpoint("GET", "/v1/items"))),
            None
        );
    }

    #[test]
    fn detail_popup_renders_proposal_review_metadata() {
        let endpoint = NetworkEndpoint {
            host: "api.example.com".to_string(),
            port: 443,
            ..Default::default()
        };
        let mut chunk = chunk_with_endpoint(endpoint);
        chunk.status = "rejected".to_string();
        chunk.rule_name = "example API access".to_string();
        chunk.rationale = "Update docs".to_string();
        chunk.validation_result = "prover: findings".to_string();
        chunk.rejection_reason = "Use a narrower path".to_string();
        chunk.hit_count = 1;

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| {
                draw_detail_popup(frame, &chunk, frame.size(), &crate::theme::Theme::dark());
            })
            .expect("draw detail popup");

        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        assert!(rendered.contains("example API access"));
        assert!(rendered.contains("Validation: prover: findings"));
        assert!(rendered.contains("Broad L4 access"));
        assert!(rendered.contains("Agent intent: Update docs"));
        assert!(rendered.contains("Reviewer guidance: Use a narrower path"));
    }
}
