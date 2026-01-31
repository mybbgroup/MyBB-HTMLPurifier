<?php
/**
 * This file is part of HTMLPurifier plugin for MyBB.
 * Copyright (C) 2011 Andreas Klauer <Andreas.Klauer@metamorpher.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// Disallow direct access to this file for security reasons
if (!defined('IN_MYBB')) {
    die('Direct initialization of this file is not allowed.<br /><br />Please make sure IN_MYBB is defined.');
}

/* --- Plugin API: --- */

function htmlpurifier_info(): array
{
    return array(
        'name' => 'HTMLPurifier for MyBB',
        'description' => "Remove malicious code from HTML in posts. Depends on <a href=\"http://htmlpurifier.org/\"><img src=\"http://htmlpurifier.org/live/art/powered.png\" alt=\"Powered by HTML Purifier\" border=\"0\" /> library</a>.",
        'website' => 'https://github.com/frostschutz/HTMLPurifier-MyBB',
        'author' => 'Andreas Klauer',
        'authorsite' => 'mailto:Andreas.Klauer@metamorpher.de',
        'version' => '1.0',
        'guid' => 'b27ff3ca01fe7fa37927416e86d48fae',
        'compatibility' => '18*,19*'
    );
}

function htmlpurifier_activate(): void
{
    if (!is_dir(MYBB_ROOT . 'cache/htmlpurifier')) {
        mkdir(MYBB_ROOT . 'cache/htmlpurifier');
    }

    if (file_exists(MYBB_ROOT . 'inc/plugins/htmlpurifier/vendor/autoload.php')) {
        require_once MYBB_ROOT . 'inc/plugins/htmlpurifier/vendor/autoload.php';
    }

    if (!class_exists('HTMLPurifier')) {
        flash_message(
            'The <a href="http://htmlpurifier.org/"><img src="http://htmlpurifier.org/live/art/powered.png" alt="Powered by HTML Purifier" border="0" /> library</a> is missing. Please download it and upload the contents of the <em>library/</em> folder to <em>inc/plugins/htmlpurifier/</em>',
            'error'
        );
        admin_redirect('index.php?module=config-plugins');
    }

    if (!is_writable(MYBB_ROOT . 'cache/htmlpurifier/')) {
        flash_message('Please create a directory <em>cache/htmlpurifier</em> and make it writable.', 'error');
        admin_redirect('index.php?module=config-plugins');
    }
}

/* --- Hooks: --- */

global $plugins, $settings;

$plugins->add_hook('datahandler_post_validate_thread', 'htmlpurifier_post');
$plugins->add_hook('datahandler_post_validate_post', 'htmlpurifier_post');

if (!empty($settings['pmsallowhtml'])) {
    $plugins->add_hook('datahandler_pm_validate', 'htmlpurifier_pm');
}

if (!empty($settings['sightml'])) {
    $plugins->add_hook('usercp_do_editsig_start', 'htmlpurifier_sig_ucp');
}

/* --- Functions: --- */

/**
 * Filter HTML when posting.
 */
function htmlpurifier_post(PostDataHandler $handler): void
{
    $forum = get_forum($handler->data['fid']);

    if (!empty($forum['allowhtml']) && !empty($handler->data['message'])) {
        $handler->data['message'] = htmlpurifier_do(
            $handler->data['message'],
            !empty($forum['allowmycode'])
        );
    }
}

/**
 * Filter HTML in PM
 */
function htmlpurifier_pm(PMDataHandler $handler): void
{
    if (!empty($handler->data['message'])) {
        global $settings;

        $handler->data['message'] = htmlpurifier_do(
            $handler->data['message'],
            !empty($settings['pmsallowmycode'])
        );
    }
}

/**
 * Filter HTML in Signature
 */
function htmlpurifier_sig_ucp(): void
{
    global $mybb;

    if (!empty($mybb->input['signature'])) {
        $mybb->input['signature'] = htmlpurifier_do(
            $mybb->input['signature'],
            !empty($mybb->settings['sigmycode'])
        );
    }
}

/**
 * Purify HTML.
 */
function htmlpurifier_do(string $html, bool $allow_mycode = false): string
{
    require_once MYBB_ROOT . 'inc/plugins/htmlpurifier/vendor/autoload.php';

    // Special treatment for code tags.
    if ($allow_mycode) {
        $html = preg_replace_callback(
            "#\[(code|php)\](.*?)\[/\\1\]#si",
            function (array $matches): string {
                return htmlspecialchars($matches[0]);
            },
            $html
        );
    }

    $config = HTMLPurifier_Config::createDefault();
    $config->set('Cache.SerializerPath', MYBB_ROOT . 'cache/htmlpurifier');
    $purifier = new HTMLPurifier($config);
    $html = $purifier->purify($html);

    // Revert special treatment for code tags.
    if ($allow_mycode) {
        $html = preg_replace_callback(
            "#\[(code|php)\](.*?)\[/\\1\]#si",
            function (array $matches): string {
                return htmlspecialchars_decode($matches[0]);
            },
            $html
        );
    }

    return $html;
}

/* --- End of file. --- */