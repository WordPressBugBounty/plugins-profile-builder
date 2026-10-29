<?php
if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

/**
 * Function that changes the auto generated password with the one selected by the user.
 */
function wppb_signup_password_random_password_filter( $password ) {
	global $wpdb;

	$key = ( !empty( $_GET['key'] ) ? sanitize_text_field( $_GET['key'] ) : null );
	$key = ( !empty( $_POST['key'] ) ? sanitize_text_field( $_POST['key'] ) : $key );

    if ( !is_null( $key ) ) {
		$signup = ( is_multisite() ? $wpdb->get_row( $wpdb->prepare( "SELECT * FROM " . $wpdb->signups . " WHERE activation_key = %s", $key ) ) : $wpdb->get_row( $wpdb->prepare( "SELECT * FROM " . $wpdb->base_prefix . "signups WHERE activation_key = %s", $key ) ) );
		
		if ( empty( $signup ) || $signup->active ) {
			//bad key or already active
		} else {
			//check for password in signup meta
			$meta = unserialize( $signup->meta );
			
			if ( !empty($meta['user_pass']) )
                $password = $meta['user_pass'];
		}
	}
	
	return apply_filters( 'wppb_generated_random_password', $password, $key );
}
add_filter( 'random_password', 'wppb_signup_password_random_password_filter' );

/**
 * Activate a signup.
 *
 *
 * @param string $key The activation key provided to the user.
 * @return array An array containing information about the activated user and/or blog
 */
function wppb_activate_signup( $key ) {
	global $wpdb;
	$bloginfo = get_bloginfo( 'name' );
	$wppb_general_settings = get_option( 'wppb_general_settings' );

    $login_after_register = ( isset( $wppb_general_settings['automaticallyLogIn'] ) ? $wppb_general_settings['automaticallyLogIn'] : apply_filters( 'wppb_automatically_login_after_register', 'No' ) );

	$signup = ( is_multisite() ? $wpdb->get_row( $wpdb->prepare("SELECT * FROM $wpdb->signups WHERE activation_key = %s", $key) ) : $wpdb->get_row( $wpdb->prepare( "SELECT * FROM ".$wpdb->base_prefix."signups WHERE activation_key = %s", $key ) ) );

	if( empty( $signup ) )
		return apply_filters( 'wppb_register_activate_user_error_message6', '<p class="error" role="alert">'.__( 'Could not find registration. Contact administrator.', 'profile-builder' ).'</p>');

    $user_login = ( ( isset( $wppb_general_settings['loginWith'] ) && ( $wppb_general_settings['loginWith'] == 'email' ) ) ? trim( $signup->user_email ) : trim( $signup->user_login ) );

    $user_email = esc_sql( $signup->user_email );
    /* Signup meta holds the real password hash, applied after user creation. WordPress requires a non-empty user_pass when creating users. */
    $password = '';

	$user_id = ( ( isset( $wppb_general_settings['loginWith'] ) && ( $wppb_general_settings['loginWith'] == 'email' ) ) ? email_exists( $user_login ) : username_exists( $user_login ) );

	if ( empty( $signup ) )
		return apply_filters( 'wppb_register_activate_user_error_message1', '<p class="error" role="alert">'.__( 'Invalid activation key!', 'profile-builder' ).'</p>');

	if ( $signup->active )
		if ( empty( $signup->domain ) )
			return apply_filters( 'wppb_register_activate_user_error_message2', '<p class="wppb-success" role="alert">'.__( 'This username is now active!', 'profile-builder' ).'</p>', $user_id );

	$meta = unserialize( $signup->meta );

    if( strcasecmp($login_after_register, 'Yes') === 0 ) {
        $login_after_register = true;
    } elseif( isset( $meta [ 'wppb_login_after_register_'.$meta['user_login'] ] ) ) {
        $login_after_register = $meta [ 'wppb_login_after_register_'.$meta['user_login'] ];
        unset( $meta [ 'wppb_login_after_register_'.$meta['user_login'] ] );
    } else {
        $login_after_register = false;
    }

	if ( ! $user_id ) {
		$user_id = wppb_create_user( $user_login, wp_generate_password( 24, true, true ), $user_email );
	}
	else
		$user_already_exists = true;

	if ( ! $user_id )
		return apply_filters( 'wppb_register_activate_user_error_message4', '<p class="error" role="alert">'.__('Could not create user!', 'profile-builder').'</p>' );
		
	elseif ( isset( $user_already_exists ) && ( $user_already_exists == true ) )
		return apply_filters( 'wppb_register_activate_user_error_message5', '<p class="error" role="alert">'.__( 'This username is already activated!', 'profile-builder' ).'</p>' );
	
	else{
		$inserted_user = ( is_multisite() ? $wpdb->update( $wpdb->signups, array( 'active' => 1, 'activated' => current_time( 'mysql', true ) ), array( 'activation_key' => $key ) ) : $wpdb->update( $wpdb->base_prefix.'signups', array( 'active' => 1, 'activated' => current_time( 'mysql', true ) ), array( 'activation_key' => $key ) ) );

		wppb_add_meta_to_user_on_activation( $user_id, '', $meta );
		
		// if admin approval is activated, then block the user until he gets approved
		$wppb_generalSettings = get_option('wppb_general_settings');
		if( wppb_get_admin_approval_option_value() === 'yes' ){
            wppb_update_user_status_to_pending( $user_id, $wppb_generalSettings );
		}

        if ( !isset( $wppb_generalSettings['adminApproval'] ) )
            $wppb_generalSettings['adminApproval'] = 'no';

        /* copy the hashed password from signup meta to wp user table */
        if( !empty( $meta['user_pass'] ) ){
            /* we might still have the base64 encoded password in signups and not the hash */
            if( base64_encode(base64_decode($meta['user_pass'], true)) === $meta['user_pass'] )
                $meta['user_pass'] = wp_hash_password( $meta['user_pass'] );

            $wpdb->update( $wpdb->users, array('user_pass' => $meta['user_pass'] ), array('ID' => $user_id) );
			wp_cache_delete( $user_id, 'users' );
        }

		wppb_notify_user_registration_email($bloginfo, $user_login, $user_email, 'sending', $password, wppb_get_admin_approval_option_value() );

		do_action( 'wppb_activate_user', $user_id, $password, $meta );

		if( $inserted_user ) {
            // CHECK FOR REDIRECT
            $redirect_url = wppb_get_redirect_url( 'normal', 'after_success_email_confirmation', '', $user_login );

            $redirect_delay = apply_filters( 'wppb_success_email_confirmation_redirect_delay', 3, $user_id );
            $redirect_message = wppb_build_redirect( $redirect_url, $redirect_delay, 'after_success_email_confirmation' );
			$redirect_message = apply_filters( 'wppb_ec_sucess_message_redirect', $redirect_message, $meta );

			$success_message = apply_filters( 'wppb_success_email_confirmation', '<p class="wppb-success" role="alert">' . __( 'Your email was successfully confirmed.', 'profile-builder' ) . '</p><!-- .success -->', $user_id );
            $admin_approval_message = apply_filters( 'wppb_email_confirmation_with_admin_approval', '<p class="alert" role="alert">' . __( 'Before you can access your account, an administrator needs to approve it. You will be notified via email.', 'profile-builder' ) . '</p>', $user_id );

            $wppb_general_settings = get_option( 'wppb_general_settings', 'false' );

            if ( wppb_get_admin_approval_option_value() === 'yes' ){
				$user_data = get_userdata( $user_id );

				if( $wppb_general_settings != 'not_found' && ! empty( $wppb_general_settings['adminApprovalOnUserRole'] ) ) {
					foreach( $user_data->roles as $role ) {
						if( in_array( $role, $wppb_general_settings['adminApprovalOnUserRole'] ) ) {
							return $success_message . $admin_approval_message . ( ! empty ( $redirect_message ) ? $redirect_message : '' );
						} else {
							wp_set_object_terms( $user_id, NULL, 'user_status' );
							clean_object_term_cache( $user_id, 'user_status' );

                            if( $login_after_register ) {
                                if( empty( $redirect_url ) ) {
                                    $redirect_url = wppb_curpageurl();
                                }
                                $redirect_message = wppb_activate_signup_autologin_redirect_url($user_id, $redirect_url, $redirect_delay);
                                $redirect_message = apply_filters( 'wppb_ec_sucess_message_redirect', $redirect_message, $meta );
                            }

							return $success_message . ( ! empty ( $redirect_message ) ? $redirect_message : '' );
						}
					}
				} else {
					return $success_message . $admin_approval_message . ( ! empty ( $redirect_message ) ? $redirect_message : '' );
				}
            } else {
				wp_set_object_terms( $user_id, NULL, 'user_status' );
				clean_object_term_cache( $user_id, 'user_status' );

                if( $login_after_register ) {
                    if( empty( $redirect_url ) ) {
                        $redirect_url = wppb_curpageurl();
                    }
                    $redirect_message = wppb_activate_signup_autologin_redirect_url($user_id, $redirect_url, $redirect_delay);
                    $redirect_message = apply_filters( 'wppb_ec_sucess_message_redirect', $redirect_message, $meta );
                }

                return $success_message . ( ! empty ( $redirect_message ) ? $redirect_message : '' );
            }
        } else {
			return apply_filters('wppb_register_failed_user_activation', '<p class="error" role="alert">'. __('There was an error while trying to activate the user.', 'profile-builder') .'</p><!-- .error -->');
        }
	}		
}

//function that generates the redirect message when the user should be automatically logged in
function wppb_activate_signup_autologin_redirect_url( $user_id, $redirect_url, $redirect_delay ){
    $redirect_url = remove_query_arg( 'activation_key' ,$redirect_url );

    $redirect_url = apply_filters( 'wppb_login_after_reg_redirect_url', $redirect_url );
    $redirect_url = add_query_arg( wppb_get_autologin_query_args( $user_id ), $redirect_url );

    return wppb_build_redirect( $redirect_url, $redirect_delay, 'after_success_email_confirmation' );
}

//function to display the registration page
function wppb_front_end_register( $atts ){

	$atts = shortcode_atts( array(
		'role'                => get_option( 'default_role' ),
		'form_name'           => 'unspecified',
		'redirect_url'        => '',
		'logout_redirect_url' => '',
		'automatic_login'     => '',
		'redirect_priority'   => 'normal',
        'ajax'                => false
	), $atts, 'wppb-register' );

	/* every builder (shortcode, block, Elementor, Divi) renders post content through here, so the post author decides what the form may do */
	if( doing_filter( 'the_content' ) ){
		/* a Query Loop swaps in the looped post before rendering the register block, and loops such as core Latest Posts or
		   the Divi Builder plugin slider render a looped post's content outside its own the_content, so check the current
		   post and every post in the_content */
		$container_ids = wppb_register_form_container_post_ids();

		foreach( $container_ids as $container_id ){
			if( ! wppb_register_form_author_can_publish( $container_id ) )
				return wppb_register_form_author_not_allowed_message();
		}

		foreach( $container_ids as $container_id ){
			if( ! wppb_register_form_author_can_assign_role( $container_id, $atts['role'] ) ){
				$atts['role'] = get_option( 'default_role' );
				break;
			}
		}
	}

    $form = new Profile_Builder_Form_Creator( array( 'form_type' => 'register', 'form_name' => $atts['form_name'], 'role' => ( is_object( get_role( $atts['role'] ) ) ? $atts['role'] : get_option( 'default_role' ) ) , 'redirect_url' => $atts['redirect_url'], 'logout_redirect_url' => $atts['logout_redirect_url'], 'automatic_login' => $atts['automatic_login'], 'redirect_priority' => $atts['redirect_priority'], 'ajax' => $atts['ajax'] ) );

    return $form;
}

// function to choose whether to display the registration page or the validation message
function wppb_front_end_register_handler( $atts ){
	return ( isset( $_GET['activation_key'] ) ? wppb_activate_signup ( sanitize_text_field( $_GET['activation_key'] ) ) : wppb_front_end_register( $atts ) );
}

add_action( 'user_register', 'wppbc_disable_admin_approval_for_user_role', 99, 1 );
function wppbc_disable_admin_approval_for_user_role( $user_id ) {
	if ( current_user_can( 'delete_users' ) ) {
		wp_set_object_terms( $user_id, NULL, 'user_status' );
		clean_object_term_cache( $user_id, 'user_status' );
	}
}

function wppb_register_push_content_post( $content ){
	$GLOBALS['wppb_register_content_post_stack'][] = (int) get_the_ID();

	return $content;
}
add_filter( 'the_content', 'wppb_register_push_content_post', 0 );

function wppb_register_pop_content_post( $content ){
	if( ! empty( $GLOBALS['wppb_register_content_post_stack'] ) )
		array_pop( $GLOBALS['wppb_register_content_post_stack'] );

	return $content;
}
add_filter( 'the_content', 'wppb_register_pop_content_post', PHP_INT_MAX );

/* blocks pull text the post author didn't write into the content (excerpts, titles, comments, feeds, shortcodes a nested
   the_content left escaped), and the do_shortcode() after do_blocks() would turn a register shortcode in that text into a
   form gated by this post's author, so tag the shortcodes the content has before do_blocks() and disarm untagged ones in
   the blocks it renders */
function wppb_register_tag_content_shortcodes( $content ){
	$GLOBALS['wppb_register_rendering_blocks'][ wppb_register_content_depth() ] = true;

	return wppb_register_tag_shortcodes( $content );
}
add_filter( 'the_content', 'wppb_register_tag_content_shortcodes', 8 );

function wppb_register_untag_content_shortcodes( $content ){
	unset( $GLOBALS['wppb_register_rendering_blocks'][ wppb_register_content_depth() ] );

	return str_replace( '[wppb-register ' . wppb_register_shortcode_tag(), '[wppb-register', $content );
}
add_filter( 'the_content', 'wppb_register_untag_content_shortcodes', 10 );

/* per block rather than a the_content filter after do_blocks(), since wp_trim_excerpt() re-adds do_blocks() behind any
   other priority 9 filter */
function wppb_register_disarm_block_shortcodes( $block_content ){
	if( ! wppb_register_rendering_content_blocks() || false === strpos( $block_content, '[wppb-register' ) )
		return $block_content;

	return preg_replace( '/\[(?=wppb-register(?![\w-])(?! ' . wppb_register_shortcode_tag() . '))/', '&#91;', $block_content );
}
add_filter( 'render_block', 'wppb_register_disarm_block_shortcodes' );

/* embed HTML holds the title of the embedded post or remote page, and core embeds before the register shortcodes are
   tagged, both in the_content (same priority, registered first) and in a synced pattern. &#091; rather than &#91;, since
   the do_shortcode() that runs [embed] turns &#91; back into [ */
function wppb_register_disarm_embed_shortcodes( $html ){
	return preg_replace( '/\[(?=wppb-register(?![\w-]))/', '&#091;', $html );
}
add_filter( 'embed_oembed_html', 'wppb_register_disarm_embed_shortcodes' );

/* a synced pattern is its author's content, so its register shortcodes stay when that author could publish them */
function wppb_register_tag_pattern_shortcodes( $parsed_block, $source_block, $parent_block = null ){
	if( ! wppb_register_rendering_content_blocks() || empty( $parent_block ) || 'core/block' !== $parent_block->name || empty( $parent_block->parsed_block['attrs']['ref'] ) || ! wppb_register_form_author_can_publish( $parent_block->parsed_block['attrs']['ref'] ) )
		return $parsed_block;

	array_walk_recursive( $parsed_block, function( &$value ){
		if( is_string( $value ) )
			$value = wppb_register_tag_shortcodes( $value );
	} );

	return $parsed_block;
}
add_filter( 'render_block_data', 'wppb_register_tag_pattern_shortcodes', 10, 3 );

function wppb_register_content_depth(){
	return empty( $GLOBALS['wppb_register_content_post_stack'] ) ? 0 : count( $GLOBALS['wppb_register_content_post_stack'] );
}

/* only blocks rendered by the innermost the_content's do_blocks(), so block widgets, templates and shortcodes that render
   blocks keep their register shortcodes */
function wppb_register_rendering_content_blocks(){
	return ! empty( $GLOBALS['wppb_register_rendering_blocks'][ wppb_register_content_depth() ] );
}

function wppb_register_tag_shortcodes( $text ){
	if( false === strpos( $text, '[wppb-register' ) )
		return $text;

	$tag = wppb_register_shortcode_tag();

	return preg_replace( '/\[wppb-register(?![\w-])(?! ' . $tag . ')/', '[wppb-register ' . $tag, $text );
}

/* random per request, so text stored in the database can't carry it */
function wppb_register_shortcode_tag(){
	static $tag = null;

	if( null === $tag )
		$tag = 'wppb' . bin2hex( random_bytes( 8 ) );

	return $tag;
}

function wppb_register_form_container_post_ids(){
	$ids   = empty( $GLOBALS['wppb_register_content_post_stack'] ) ? array() : $GLOBALS['wppb_register_content_post_stack'];
	$ids[] = (int) get_the_ID();

	return array_unique( array_filter( $ids ) );
}

function wppb_register_form_author_can_publish( $post_id ){
	$post = get_post( $post_id );

	if( empty( $post ) || empty( $post->post_author ) )
		return true;

	return user_can( $post->post_author, 'edit_others_posts' );
}

/* a role set in post content can't grant capabilities its author doesn't have, unless the author can change user roles anyway */
function wppb_register_form_author_can_assign_role( $post_id, $role ){
	$post        = get_post( $post_id );
	$role_object = get_role( $role );

	if( empty( $post ) || empty( $post->post_author ) || empty( $role_object ) || user_can( $post->post_author, 'promote_users' ) )
		return true;

	/* compare granted capabilities, since user_can() maps some (like manage_links) to do_not_allow regardless of role */
	$author = get_userdata( $post->post_author );

	return ! empty( $author ) && empty( array_diff_key( array_filter( $role_object->capabilities ), array_filter( $author->allcaps ) ) );
}

function wppb_register_form_author_not_allowed_message(){
	return '<p class="alert wppb-error" role="alert">' . esc_html__( 'Only an administrator can create pages with a registration form.', 'profile-builder' ) . '</p>';
}

/* custom redirect after registration on wp default register form */
function wppb_default_registration_redirect( $user_id ) {

    $user_data = get_userdata( $user_id );

    // CHECK FOR REDIRECT
    if( isset( $_POST['redirect_to']  ) )
        $_POST['redirect_to'] = apply_filters( 'wppb_after_registration_redirect_url', wppb_get_redirect_url( 'normal', 'after_registration', wppb_sanitize_request_url( $_POST['redirect_to'] ), $user_data ) );

}
add_action( 'register_new_user', 'wppb_default_registration_redirect' );
