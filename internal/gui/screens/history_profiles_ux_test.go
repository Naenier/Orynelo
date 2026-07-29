package screens

import (
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/Naenier/opsdoctor/internal/gui/localization"
	"github.com/Naenier/opsdoctor/internal/gui/presenter"
)

func TestHistoryUsesReadableToolbarAndSelectionActions(t *testing.T) {
	test.NewTempApp(t)
	openedID := ""
	lastSearch := ""
	screen := NewHistory(localization.English{}, HistoryActions{
		Load: func(search, _ string) ([]presenter.HistoryView, error) {
			lastSearch = search
			return nil, nil
		},
		Open: func(row presenter.HistoryView) {
			openedID = row.ID
		},
		Rerun:  func(presenter.HistoryView) {},
		Export: func(presenter.HistoryView) {},
		Delete: func(presenter.HistoryView) {},
		Clear:  func() {},
	})
	screen.Root.Resize(fyne.NewSize(1000, 620))
	test.LaidOutObjects(screen.Root)

	if screen.Root.MinSize().Width > 830 {
		t.Fatalf(
			"history minimum width = %.0f, want at most 830",
			screen.Root.MinSize().Width,
		)
	}
	if screen.search.Size().Width < 280 {
		t.Fatalf("history search width = %.0f, want a readable field", screen.search.Size().Width)
	}
	if screen.status.Size().Width < 150 || screen.order.Size().Width < 170 {
		t.Fatalf(
			"history select widths = %.0f/%.0f, want readable filters",
			screen.status.Size().Width,
			screen.order.Size().Width,
		)
	}
	if screen.refresh.Size().Width > 180 {
		t.Fatalf("history refresh width = %.0f, want a compact action", screen.refresh.Size().Width)
	}
	if historyColumnsWidth > 800 {
		t.Fatalf(
			"history column width total = %.0f, want at most 800",
			historyColumnsWidth,
		)
	}
	if !screen.empty.Visible() || screen.list.Visible() {
		t.Fatal("empty history does not show its dedicated empty state")
	}
	if screen.emptyCard.Title !=
		screen.texts.Text(localization.HistoryEmptyTitle) ||
		screen.emptyCard.Subtitle !=
			screen.texts.Text(localization.HistoryEmptyHint) {
		t.Fatalf(
			"history empty copy = %q / %q",
			screen.emptyCard.Title,
			screen.emptyCard.Subtitle,
		)
	}
	if screen.actionBar.Visible() {
		t.Fatal("empty history exposes row actions")
	}
	if !screen.open.Disabled() || !screen.rerun.Disabled() ||
		!screen.export.Disabled() || !screen.delete.Disabled() ||
		!screen.clear.Disabled() {
		t.Fatal("history actions are enabled without rows or selection")
	}

	screen.SetRows([]presenter.HistoryView{
		{
			ID:       "newer",
			Date:     time.Date(2026, 7, 28, 15, 42, 44, 0, time.UTC),
			Target:   "https://newer.example",
			Status:   "failed",
			Duration: time.Second,
			Version:  "dev",
		},
		{
			ID:       "older",
			Date:     time.Date(2026, 7, 28, 14, 42, 44, 0, time.UTC),
			Target:   "https://older.example",
			Status:   "passed",
			Duration: time.Millisecond,
			Version:  "dev",
		},
	})
	if screen.empty.Visible() || !screen.list.Visible() {
		t.Fatal("loaded history did not replace the empty state")
	}
	if !screen.actionBar.Visible() {
		t.Fatal("loaded history did not expose its action bar")
	}
	if screen.clear.Disabled() {
		t.Fatal("clear history remains disabled when rows are visible")
	}
	screen.Root.Resize(fyne.NewSize(830, 620))
	test.LaidOutObjects(screen.Root)
	smallTargetWidth := screen.columnLayout.targetWidth
	smallVersionWidth := screen.columnLayout.versionWidth
	if smallTargetWidth < historyTargetColumnWidth ||
		smallVersionWidth < historyVersionColumnWidth {
		t.Fatalf(
			"minimum history flexible widths = %.0f/%.0f",
			smallTargetWidth,
			smallVersionWidth,
		)
	}
	screen.Root.Resize(fyne.NewSize(1400, 620))
	test.LaidOutObjects(screen.Root)
	if screen.columnLayout.targetWidth <= smallTargetWidth ||
		screen.columnLayout.versionWidth <= smallVersionWidth {
		t.Fatalf(
			"history columns did not grow responsively: %.0f/%.0f -> %.0f/%.0f",
			smallTargetWidth,
			smallVersionWidth,
			screen.columnLayout.targetWidth,
			screen.columnLayout.versionWidth,
		)
	}
	availableFlexible := screen.listPane.Size().Width -
		4*theme.Size(theme.SizeNamePadding) -
		historyDateColumnWidth -
		historyStatusColumnWidth -
		historyDurationColumnWidth
	actualFlexible := screen.columnLayout.targetWidth +
		screen.columnLayout.versionWidth
	if actualFlexible < availableFlexible-1 ||
		actualFlexible > availableFlexible+1 {
		t.Fatalf(
			"responsive history widths = %.0f, want %.0f",
			actualFlexible,
			availableFlexible,
		)
	}

	screen.list.Select(1)
	if screen.selected != 1 {
		t.Fatalf("selected history row = %d, want 1", screen.selected)
	}
	if screen.open.Disabled() || screen.rerun.Disabled() ||
		screen.export.Disabled() || screen.delete.Disabled() {
		t.Fatal("row-specific history actions remain disabled after selection")
	}
	test.Tap(screen.open)
	if openedID != "older" {
		t.Fatalf("opened history ID = %q, want older", openedID)
	}

	screen.order.SetSelected(screen.texts.Text(localization.HistoryOldestFirst))
	if screen.selected != -1 || !screen.open.Disabled() {
		t.Fatal("sorting retained a stale history selection")
	}
	if screen.filtered[0].ID != "older" {
		t.Fatalf("oldest-first row = %q, want older", screen.filtered[0].ID)
	}

	screen.search.SetText("does-not-exist")
	screen.Reload()
	if screen.emptyCard.Title !=
		screen.texts.Text(localization.HistoryNoMatchesTitle) ||
		screen.emptyCard.Subtitle !=
			screen.texts.Text(localization.HistoryNoMatchesHint) {
		t.Fatalf(
			"history no-match copy = %q / %q",
			screen.emptyCard.Title,
			screen.emptyCard.Subtitle,
		)
	}
	if screen.emptyRefresh.Visible() || !screen.emptyClear.Visible() {
		t.Fatal("history no-match state does not offer clear filters")
	}
	test.Tap(screen.emptyClear)
	if lastSearch != "" || screen.search.Text != "" {
		t.Fatal("clear history filters did not reload the unfiltered history")
	}
}

func TestProfilesToolbarEmptyStateAndSelectionActions(t *testing.T) {
	test.NewTempApp(t)
	ranID := int64(0)
	screen := NewProfiles(localization.English{}, ProfileActions{
		Load: func() ([]presenter.ProfileView, error) {
			return nil, nil
		},
		Create: func() {},
		Edit:   func(presenter.ProfileView) {},
		Duplicate: func(presenter.ProfileView) error {
			return nil
		},
		Delete: func(presenter.ProfileView) {},
		Run: func(profile presenter.ProfileView) {
			ranID = profile.ID
		},
	})
	screen.Root.Resize(fyne.NewSize(900, 620))
	test.LaidOutObjects(screen.Root)

	if screen.Root.MinSize().Width > 830 {
		t.Fatalf(
			"profiles minimum width = %.0f, want at most 830",
			screen.Root.MinSize().Width,
		)
	}
	if screen.search.Size().Width < 400 {
		t.Fatalf("profiles search width = %.0f, want a readable field", screen.search.Size().Width)
	}
	if screen.refresh.Size().Width > 180 {
		t.Fatalf("profiles refresh width = %.0f, want a compact action", screen.refresh.Size().Width)
	}
	if !screen.empty.Visible() || screen.list.Visible() {
		t.Fatal("empty profiles do not show their dedicated empty state")
	}
	if screen.actionBar.Visible() {
		t.Fatal("empty profiles expose selection actions")
	}
	if screen.emptyCard.Title !=
		screen.texts.Text(localization.ProfilesEmptyTitle) ||
		screen.emptyCard.Subtitle !=
			screen.texts.Text(localization.ProfilesEmptyHint) {
		t.Fatalf(
			"profiles empty copy = %q / %q",
			screen.emptyCard.Title,
			screen.emptyCard.Subtitle,
		)
	}
	if !screen.emptyCreate.Visible() || screen.emptyClear.Visible() {
		t.Fatal("profile empty state exposes the wrong primary action")
	}
	if screen.create.Disabled() {
		t.Fatal("create profile is disabled in the empty state")
	}
	if !screen.run.Disabled() || !screen.edit.Disabled() ||
		!screen.duplicate.Disabled() || !screen.delete.Disabled() {
		t.Fatal("profile actions are enabled without a selection")
	}

	screen.SetProfiles([]presenter.ProfileView{
		{
			ID:        1,
			Name:      "Production",
			Target:    "https://prod.example",
			Mode:      "auto",
			IPVersion: "auto",
			Method:    "GET",
		},
		{
			ID:        2,
			Name:      "Staging",
			Target:    "https://staging.example",
			Mode:      "tls",
			IPVersion: "4",
			Method:    "HEAD",
		},
	})
	if screen.empty.Visible() || !screen.list.Visible() {
		t.Fatal("loaded profiles did not replace the empty state")
	}
	if !screen.actionBar.Visible() {
		t.Fatal("loaded profiles did not expose their action bar")
	}

	item := screen.list.CreateItem()
	screen.list.UpdateItem(0, item)
	target := item.(*fyne.Container).Objects[1].(*widget.Label)
	if target.Text != "Target: https://prod.example" {
		t.Fatalf("profile target row = %q", target.Text)
	}
	if target.Truncation != fyne.TextTruncateEllipsis {
		t.Fatal("long profile targets are not truncated safely")
	}
	settings := item.(*fyne.Container).Objects[2].(*widget.Label)
	if settings.Text != "Mode Auto · IP Auto · GET" {
		t.Fatalf("profile settings row = %q", settings.Text)
	}

	screen.list.Select(1)
	if screen.selected != 1 {
		t.Fatalf("selected profile = %d, want 1", screen.selected)
	}
	if screen.run.Disabled() || screen.edit.Disabled() ||
		screen.duplicate.Disabled() || screen.delete.Disabled() {
		t.Fatal("profile actions remain disabled after selection")
	}
	test.Tap(screen.run)
	if ranID != 2 {
		t.Fatalf("ran profile ID = %d, want 2", ranID)
	}

	screen.search.SetText("does-not-exist")
	if screen.selected != -1 || !screen.run.Disabled() {
		t.Fatal("profile search retained a stale selection")
	}
	if !screen.empty.Visible() || screen.list.Visible() {
		t.Fatal("profile search with no matches did not show the empty state")
	}
	if screen.actionBar.Visible() {
		t.Fatal("profile no-match state exposes selection actions")
	}
	if screen.emptyCard.Title !=
		screen.texts.Text(localization.ProfilesNoMatchesTitle) ||
		screen.emptyCard.Subtitle !=
			screen.texts.Text(localization.ProfilesNoMatchesHint) {
		t.Fatalf(
			"profiles no-match copy = %q / %q",
			screen.emptyCard.Title,
			screen.emptyCard.Subtitle,
		)
	}
	if screen.emptyCreate.Visible() || !screen.emptyClear.Visible() {
		t.Fatal("profile no-match state does not offer clear search")
	}
	test.Tap(screen.emptyClear)
	if screen.search.Text != "" || screen.empty.Visible() || !screen.list.Visible() {
		t.Fatal("clear profile search did not restore the profile list")
	}
}
