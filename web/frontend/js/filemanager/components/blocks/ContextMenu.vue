<template>
    <!-- Manual x/y placement keeps the menu under the cursor, and the popover
         teleports it out of `.fm-body` and the tab pane, both of which clip
         with `overflow: hidden`, and flips it when it does not fit below. -->
    <n-popover
        trigger="manual"
        placement="bottom-start"
        raw
        v-bind:show="menuVisible"
        v-bind:x="menuX"
        v-bind:y="menuY"
        v-bind:show-arrow="false"
    >
        <div
            v-bind:ref="bindMenu"
            v-bind:style="{ maxHeight: menuMaxHeight }"
            v-on:blur="closeMenu"
            v-on:keydown.esc.stop.prevent="closeMenu"
            class="fm-context-menu"
            tabindex="-1"
        >
            <template v-for="block in menuBlocks" v-bind:key="`g-${block.group}`">
                <ul v-if="block.rows.length" class="list-unstyled">
                    <template v-for="row in block.rows" v-bind:key="row.key">
                        <li v-if="row.item" v-on:click="menuAction(row.item.name)">
                            <span class="fm-context-menu-icon"><GIcon :name="row.item.icon" :class="row.item.iconClass" /></span>
                            {{ lang.contextMenu[row.item.name] }}
                        </li>
                        <li
                            v-else
                            :class="{ disabled: row.editorItem.disabled }"
                            :title="row.editorItem.disabled ? lang.contextMenu.fileTooLarge : ''"
                            @click="!row.editorItem.disabled && openPluginEditor(row.editorItem)"
                        >
                            <span class="fm-context-menu-icon"><GIcon :name="row.editorItem.editor.icon || 'edit'" /></span>
                            {{ getEditorMenuLabel(row.editorItem) }}
                        </li>
                    </template>
                </ul>
            </template>
        </div>
    </n-popover>
</template>

<script setup>
import { ref, computed, watch, onMounted, onUnmounted, nextTick } from 'vue'
import { GIcon } from '@gameap/ui'
import EventBus from '../../emitter.js'
import { isExtractable } from '../../archive.js'
import { useFileManagerStore } from '../../stores/useFileManagerStore.js'
import { useSettingsStore } from '../../stores/useSettingsStore.js'
import { useModalStore } from '../../stores/useModalStore.js'
import { useHistoryStore } from '../../stores/useHistoryStore.js'
import { useTranslate } from '../../composables/useTranslate.js'
import { useFileEditors, isFileTooLarge, loadsOwnContent } from '../../composables/useFileEditors.js'
import { usePluginsStore } from '../../../store/plugins'

const fm = useFileManagerStore()
const pluginsStore = usePluginsStore()
const settings = useSettingsStore()
const modal = useModalStore()
const history = useHistoryStore()
const { lang } = useTranslate()
const { getMatchingEditors } = useFileEditors()

// Breathing room between the menu and the edge of the viewport it is capped to.
const MENU_VIEWPORT_MARGIN = 8

const contextMenu = ref(null)
const menuVisible = ref(false)
const menuX = ref(0)
const menuY = ref(0)
const menuMaxHeight = ref('')

const selectedDisk = computed(() => fm.selectedDisk)
const selectedItems = computed(() => fm.selectedItems)
const selectedDiskDriver = computed(() => fm.disks[selectedDisk.value]?.driver)
const multiSelect = computed(() => selectedItems.value.length > 1)
const firstItemType = computed(() => selectedItems.value[0]?.type)

function canView(extension) {
    if (!extension) return false
    return settings.imageExtensions.includes(extension.toLowerCase())
}

function canEdit(extension) {
    if (!extension) return false
    return Object.keys(settings.textExtensions).includes(extension.toLowerCase())
}

function canAudioPlay(extension) {
    if (!extension) return false
    return settings.audioExtensions.includes(extension.toLowerCase())
}

function canVideoPlay(extension) {
    if (!extension) return false
    return settings.videoExtensions.includes(extension.toLowerCase())
}

// Rules
function openRule() {
    return !multiSelect.value && firstItemType.value === 'dir'
}

function audioPlayRule() {
    return (
        selectedItems.value.every((elem) => elem.type === 'file') &&
        selectedItems.value.every((elem) => canAudioPlay(elem.extension))
    )
}

function videoPlayRule() {
    return !multiSelect.value && canVideoPlay(selectedItems.value[0]?.extension)
}

function viewRule() {
    return !multiSelect.value && firstItemType.value === 'file' && canView(selectedItems.value[0]?.extension)
}

function editRule() {
    return !multiSelect.value && firstItemType.value === 'file' && canEdit(selectedItems.value[0]?.extension)
}

function selectRule() {
    return !multiSelect.value && firstItemType.value === 'file' && fm.fileCallback
}

function downloadRule() {
    return !multiSelect.value && firstItemType.value === 'file'
}

function downloadDirRule() {
    return !multiSelect.value && firstItemType.value === 'dir'
}

function copyRule() {
    return true
}

function cutRule() {
    return true
}

function renameRule() {
    return !multiSelect.value
}

function chmodRule() {
    return selectedItems.value.length > 0
}

function pasteRule() {
    return !!fm.clipboard.type
}

function zipRule() {
    return selectedItems.value.length > 0
}

function unzipRule() {
    return (
        !multiSelect.value &&
        firstItemType.value === 'file' &&
        isExtractable(selectedItems.value[0]?.basename)
    )
}

function hashRule() {
    return selectedItems.value.length === 1 && selectedItems.value[0].type === 'file'
}

function deleteRule() {
    return true
}

function propertiesRule() {
    return !multiSelect.value
}

const rules = {
    open: openRule,
    audioPlay: audioPlayRule,
    videoPlay: videoPlayRule,
    view: viewRule,
    edit: editRule,
    select: selectRule,
    download: downloadRule,
    downloadDir: downloadDirRule,
    copy: copyRule,
    cut: cutRule,
    rename: renameRule,
    chmod: chmodRule,
    paste: pasteRule,
    zip: zipRule,
    unzip: unzipRule,
    hash: hashRule,
    delete: deleteRule,
    properties: propertiesRule,
}

function noteFileOpened() {
    const item = selectedItems.value[0]
    if (!item) return

    history.noteFileOpened({
        disk: selectedDisk.value,
        path: item.path,
        dirname: item.dirname,
    })
}

// Actions
function openAction() {
    fm.selectDirectory(fm.activeManager, {
        path: selectedItems.value[0].path,
        history: true,
    })
}

function audioPlayAction() {
    modal.setModalState({ modalName: 'AudioPlayerModal', show: true })
    noteFileOpened()
}

function videoPlayAction() {
    modal.setModalState({ modalName: 'VideoPlayerModal', show: true })
    noteFileOpened()
}

function viewAction() {
    modal.setModalState({ modalName: 'PreviewModal', show: true })
    noteFileOpened()
}

function editAction() {
    modal.setModalState({ modalName: 'TextEditModal', show: true })
    noteFileOpened()
}

function selectAction() {
    fm.url({ disk: selectedDisk.value, path: selectedItems.value[0].path }).then((response) => {
        if (response.data.result.status === 'success') {
            fm.fileCallback(response.data.url)
        }
    })
}

function downloadAction() {
    fm.download({
        disk: selectedDisk.value,
        path: selectedItems.value[0].path,
        filename: selectedItems.value[0].basename,
    })
}

function downloadDirAction() {
    const item = selectedItems.value[0]
    const archiveName = `${item.basename || item.name || 'archive'}.zip`
    fm.downloadDirectory({
        disk: selectedDisk.value,
        path: item.path,
        filename: archiveName,
    }).catch(() => {
        /* errors are surfaced via the messages store */
    })
}

function copyAction() {
    fm.toClipboard('copy')
}

function cutAction() {
    fm.toClipboard('cut')
}

function renameAction() {
    modal.setModalState({ modalName: 'RenameModal', show: true })
}

function chmodAction() {
    modal.setModalState({ modalName: 'ChmodModal', show: true })
}

function pasteAction() {
    fm.paste()
}

function zipAction() {
    modal.setModalState({ modalName: 'ZipModal', show: true })
}

function unzipAction() {
    modal.setModalState({ modalName: 'UnzipModal', show: true })
}

function hashAction() {
    modal.setModalState({ modalName: 'HashModal', show: true })
}

function deleteAction() {
    modal.setModalState({ modalName: 'DeleteModal', show: true })
}

function propertiesAction() {
    modal.setModalState({ modalName: 'PropertiesModal', show: true })
}

const actions = {
    open: openAction,
    audioPlay: audioPlayAction,
    videoPlay: videoPlayAction,
    view: viewAction,
    edit: editAction,
    select: selectAction,
    download: downloadAction,
    downloadDir: downloadDirAction,
    copy: copyAction,
    cut: cutAction,
    rename: renameAction,
    chmod: chmodAction,
    paste: pasteAction,
    zip: zipAction,
    unzip: unzipAction,
    hash: hashAction,
    delete: deleteAction,
    properties: propertiesAction,
}

function showMenu(event) {
    if (!selectedItems.value.length) return

    menuMaxHeight.value = `${document.documentElement.clientHeight - MENU_VIEWPORT_MARGIN * 2}px`
    menuX.value = event.clientX
    menuY.value = event.clientY
    menuVisible.value = true
}

// The popover hangs the menu off one side of the cursor — below it, or above
// when that is the roomier side — so a menu taller than either gap would have
// to scroll even while the screen has room for all of it. Moving the anchor up
// to the lowest point the whole menu still fits at spends that room instead.
// Only a menu taller than the screen is left scrolling, capped by maxHeight.
function fitMenu(el) {
    const lowest = document.documentElement.clientHeight - MENU_VIEWPORT_MARGIN - el.offsetHeight

    if (menuY.value > lowest) {
        menuY.value = Math.max(lowest, MENU_VIEWPORT_MARGIN)
    }
}

function settleMenu() {
    const el = contextMenu.value
    if (!el) return

    // Focusing an element teleported into the body scrolls the page to it.
    el.focus({ preventScroll: true })
    fitMenu(el)
    armScrollClose()
}

// Closing on blur needs the menu focused, and the popover body is not in the
// DOM on the tick `menuVisible` flips — so this runs when the element
// appears...
function bindMenu(el) {
    contextMenu.value = el
    if (el) nextTick(settleMenu)
}

// ...and again on reopen, for the case where the menu is opened over another
// row before the closing one has finished leaving and Vue reuses the element.
watch(menuVisible, (visible) => {
    if (visible) nextTick(settleMenu)
})

function closeMenu() {
    disarmScrollClose()
    menuVisible.value = false
}

function closeMenuOnScroll(event) {
    // The popover places the menu in page coordinates, so a scroll of the page
    // carries it along with the row it was opened on. A scroller inside the
    // page — the file list above all — moves the rows on their own instead,
    // and leaves the menu pointing at whatever slid under it.
    if (event.target === document || event.target === document.scrollingElement) return

    closeMenu()
}

let scrollCloseFrame = null

// The right click focuses its row, and a row the list keeps partly out of
// sight is scrolled into view by the browser a beat after the menu is already
// up. Listening only from the next frame on leaves that scroll to the gesture
// that opened the menu, and every later one to the reader.
function armScrollClose() {
    disarmScrollClose()
    scrollCloseFrame = requestAnimationFrame(() => {
        scrollCloseFrame = null
        window.addEventListener('scroll', closeMenuOnScroll, true)
    })
}

function disarmScrollClose() {
    if (scrollCloseFrame !== null) {
        cancelAnimationFrame(scrollCloseFrame)
        scrollCloseFrame = null
    }
    window.removeEventListener('scroll', closeMenuOnScroll, true)
}

function showMenuItem(name) {
    if (rules[name]) {
        return rules[name]()
    }
    return false
}

function menuAction(name) {
    if (actions[name]) {
        actions[name]()
    }
    closeMenu()
}

const pluginEditorItems = computed(() => {
    if (multiSelect.value || firstItemType.value !== 'file') {
        return []
    }
    const file = selectedItems.value[0]
    if (!file) return []

    const fileTooLarge = isFileTooLarge(file)
    return getMatchingEditors(file).map(item => ({
        ...item,
        // The size cap is about handing the editor the file's content; an
        // editor that loads what it needs itself is offered whatever the size.
        disabled: fileTooLarge && !loadsOwnContent(item.editor)
    }))
})

// Where a plugin item goes when it names no block, and when it names one this
// panel does not know: the block plugin items had to themselves before there
// was a choice of any. An item in an unexpected block is still an item, a
// dropped one is a bug.
const PLUGIN_GROUP = 'top'

const menuBlocks = computed(() => {
    const editors = new Map(
        [PLUGIN_GROUP, ...settings.contextMenu.map((block) => block.group)].map((group) => [group, []])
    )
    for (const item of pluginEditorItems.value) {
        const named = item.editor.menuGroup
        editors.get(editors.has(named) ? named : PLUGIN_GROUP).push(item)
    }
    // One list per block, plugin items and the file manager's own in the order
    // the block asks for. Filtered here rather than in the template, so a block
    // left with nothing to show goes away together with the divider it would
    // draw.
    return [{ group: PLUGIN_GROUP, items: [] }, ...settings.contextMenu].map(({ group, items, editorsFirst }) => {
        const own = items
            .filter((item) => showMenuItem(item.name))
            .map((item) => ({ key: `i-${item.name}`, item }))
        const plugins = editors
            .get(group)
            .map((editorItem) => ({ key: `pe-${editorItem.pluginId}-${editorItem.editor.id}`, editorItem }))
        return { group, rows: editorsFirst ? [...plugins, ...own] : [...own, ...plugins] }
    })
})

function getEditorMenuLabel(editorItem) {
    // An editor that is not "Edit with X" — a viewer, a comparison — names its
    // own item, and that name goes through the plugin's translations.
    if (editorItem.editor.menuLabel) {
        return pluginsStore.resolvePluginText(editorItem.pluginId, editorItem.editor.menuLabel)
    }
    const baseName = pluginsStore.resolvePluginText(editorItem.pluginId, editorItem.editor.name)
    if (editorItem.isDefault) {
        return `Edit with ${baseName} (default)`
    }
    return `Edit with ${baseName}`
}

function openPluginEditor(editorItem) {
    modal.openPluginEditor({
        pluginId: editorItem.pluginId,
        editor: editorItem.editor,
        file: selectedItems.value[0]
    })
    noteFileOpened()
    closeMenu()
}

onMounted(() => {
    EventBus.on('contextMenu', (event) => showMenu(event))
    window.addEventListener('resize', closeMenu)
})

onUnmounted(() => {
    disarmScrollClose()
    window.removeEventListener('resize', closeMenu)
})
</script>

<style lang="scss">
.fm-context-menu {
    @apply bg-white dark:bg-stone-900 rounded border;

    // Placement and stacking belong to the popover; the cap comes in inline
    // from showMenu, and what does not fit under it scrolls.
    overflow-x: hidden;
    overflow-y: auto;

    &:focus {
        outline: none;
    }

    .list-unstyled {
        @apply border-b;
        margin-bottom: 0;

        &:last-child {
            border-bottom: none;
        }
    }

    ul > li {
        padding: 0.4rem 1rem;
    }

    ul > li:not(.disabled) {
        cursor: pointer;

        &:hover {
          @apply bg-surface-hover;
        }
    }

    ul > li.disabled {
        @apply text-faint;
        cursor: not-allowed;
    }

    // Glyph widths vary between icons; a fixed-width slot keeps every label
    // starting at the same offset.
    .fm-context-menu-icon {
        display: inline-block;
        width: 1.25em;
        margin-right: 1.5rem;
        text-align: center;
    }
}
</style>
