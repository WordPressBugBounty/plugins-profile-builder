<?php
// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) exit;

if ( get_option( 'users_can_register' ) != '1' )
    add_filter( 'wppb_register_setting_override', '__return_false' );
