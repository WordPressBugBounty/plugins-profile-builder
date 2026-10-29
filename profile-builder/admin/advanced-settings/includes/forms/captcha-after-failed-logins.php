<?php
if ( ! defined( 'ABSPATH' ) ) exit;

add_filter( 'wppb_login_captcha_required', 'wppb_captcha_after_failed_logins', 10, 3 );
function wppb_captcha_after_failed_logins( $required, $provider, $form ) {
    if ( ! $required )
        return false;

    $key = wppb_failed_logins_key();

    if ( $key !== null && (int) get_transient( $key ) < wppb_failed_logins_threshold() )
        return false;

    if ( ! defined( 'DONOTCACHEPAGE' ) )
        define( 'DONOTCACHEPAGE', true );

    if ( ! headers_sent() )
        nocache_headers();

    return true;
}

/*
 * Count at the end of the authenticate chain, not on wp_login_failed: LearnDash can exit inside
 * wp_login_failed. The final authenticate value is what wp_signon acts on.
 * A successful login leaves the count alone. Otherwise an attacker could reset it by logging in to
 * their own account between guesses.
 */
add_filter( 'authenticate', 'wppb_count_failed_login', PHP_INT_MAX );
function wppb_count_failed_login( $user ) {
    $key = wppb_failed_logins_key();

    if ( $key === null )
        return $user;

    if ( is_wp_error( $user ) && wppb_is_counted_login_failure( $user ) )
        set_transient( $key, (int) get_transient( $key ) + 1, apply_filters( 'wppb_failed_logins_window', HOUR_IN_SECONDS ) );

    return $user;
}

function wppb_is_counted_login_failure( $error ) {
    $code = $error->get_error_code();

    if ( $code === 'wppb_login_auth' )
        return ! empty( $_POST['auth'] );

    return in_array( $code, array( 'incorrect_password', 'invalid_username', 'invalid_email' ), true );
}

function wppb_failed_logins_key() {
    $ip     = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
    $bucket = wppb_failed_logins_ip_bucket( apply_filters( 'wppb_failed_logins_client_ip', $ip ) );

    if ( $bucket === null )
        return null;

    return 'wppb_failed_logins_' . wp_hash( $bucket );
}

function wppb_failed_logins_ip_bucket( $ip ) {
    if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) )
        return null;

    if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) )
        return $ip;

    $packed = inet_pton( $ip );

    if ( substr( $packed, 0, 12 ) === str_repeat( "\0", 10 ) . "\xff\xff" )
        return inet_ntop( substr( $packed, 12 ) );

    return inet_ntop( substr( $packed, 0, 8 ) . str_repeat( "\0", 8 ) ) . '/64';
}

function wppb_failed_logins_threshold() {
    return wppb_toolbox_parse_failed_login_attempts( wppb_toolbox_get_settings( 'forms', 'captcha-after-failed-logins-attempts' ) );
}
