<?php
if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly
/**
 * Function that creates the "Basic Information" submenu page
 *
 * @since v.2.0
 *
 * @return void
 */
function wppb_register_basic_info_submenu_page() {
	add_submenu_page( 'profile-builder', __( 'Basic Information', 'profile-builder' ), __( 'Basic Information', 'profile-builder' ), 'manage_options', 'profile-builder-basic-info', 'wppb_basic_info_content' );
}
add_action( 'admin_menu', 'wppb_register_basic_info_submenu_page', 2 );

/**
 * Function that adds content to the "Basic Information" submenu page
 *
 * @since v.2.0
 *
 * @return string
 */
function wppb_basic_info_content() {

	$version = 'Free';
	$version = ( ( PROFILE_BUILDER == 'Profile Builder Pro' ) ? 'Pro' : $version );
	$version = ( ( PROFILE_BUILDER == 'Profile Builder Agency' ) ? 'Agency' : $version );
	$version = ( ( PROFILE_BUILDER == 'Profile Builder Unlimited' ) ? 'Unlimited' : $version );
	$version = ( ( PROFILE_BUILDER == 'Profile Builder Basic' ) ? 'Basic' : $version );

?>
	<div class="wrap wppb-wrap wppb-info-wrap cozmoslabs-wrap">

        <h1></h1>
        <!-- WordPress Notices are added after the h1 tag -->

        <div class="cozmoslabs-page-header">
            <div>
                <h1 class="cozmoslabs-page-title"><?php echo wp_kses_post( sprintf( __( '<strong>Profile Builder </strong> %s', 'profile-builder' ), esc_html( $version ) ) ); ?></h1>
                <p class="cozmoslabs-description"><?php esc_html_e( 'The best way to add front-end registration, edit profile and login forms.', 'profile-builder' ); ?></p>
            </div>
            <div class="wppb-badge <?php echo esc_attr( $version ); ?>"><span><?php printf( esc_html__( 'Version %s', 'profile-builder' ), esc_html( PROFILE_BUILDER_VERSION ) ); ?></span></div>
        </div>


        <div class="cozmoslabs-form-subsection-wrapper" id="basic-info-shortcodes">
            <h2 class="cozmoslabs-subsection-title"><?php esc_html_e( 'Shortcodes', 'profile-builder' ); ?></h2>

            <div class="cozmoslabs-form-field-wrapper">
                <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Login Form', 'profile-builder'  ); ?></label>
                <strong>[wppb-login]</strong>
                <p class="cozmoslabs-description cozmoslabs-description-space-left">
                    <?php esc_html_e( 'Friction-less login using this shortcode or a widget.', 'profile-builder'  ); ?>
                </p>
            </div>

            <div class="cozmoslabs-form-field-wrapper">
                <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Registration Form', 'profile-builder'  ); ?></label>
                <strong>[wppb-register]</strong>
                <p class="cozmoslabs-description cozmoslabs-description-space-left">
                    <?php esc_html_e( 'Beautiful and fully customizable Registration Forms.', 'profile-builder'  ); ?>
                </p>
            </div>

            <div class="cozmoslabs-form-field-wrapper">
                <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Edit Profile Form', 'profile-builder'  ); ?></label>
                <strong>[wppb-edit-profile]</strong>
                <p class="cozmoslabs-description cozmoslabs-description-space-left">
                    <?php esc_html_e( 'Straight forward Edit Profile Forms.', 'profile-builder'  ); ?>
                </p>
            </div>

            <?php
            $wppb_pages_created    = get_option( 'wppb_pages_created' );
            $shortcode_pages_query = new WP_Query( array( 'post_type' => 'page', 's' => '[wppb-' ) );
            if( empty( $wppb_pages_created ) && !$shortcode_pages_query->have_posts() ){
                ?>
                <div class="cozmoslabs-form-field-wrapper">
                    <p class="cozmoslabs-description cozmoslabs-notice-message"><?php esc_html_e( 'Speed up the setup process by automatically creating the form pages:', 'profile-builder' ); ?></p>
                    <a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=profile-builder-basic-info&wppb_create_pages=true' ), 'wppb_create_pages' ) ) ?>" class="button button-primary"><?php esc_html_e( 'Create Form Pages', 'profile-builder' ); ?></a>
                </div>
            <?php }else{ ?>
                <div class="cozmoslabs-form-field-wrapper">
                    <p class="cozmoslabs-description cozmoslabs-notice-message"><?php esc_html_e( 'You can see all the pages with Profile Builder form shortcodes here:', 'profile-builder' ); ?></p>
                    <a href="<?php echo esc_url( admin_url( 'edit.php?s=%5Bwppb-&post_status=all&post_type=page&action=-1&m=0&paged=1&action2=-1' ) ) ?>" class="button button-secondary"><?php esc_html_e( 'View Form Pages', 'profile-builder' ); ?></a>
                </div>
            <?php } ?>

        </div>


		<?php ob_start(); ?>

        <div class="cozmoslabs-form-subsection-wrapper" id="basic-info-extra-features">
            <h2 class="cozmoslabs-subsection-title"><?php esc_html_e( 'Extra Features', 'profile-builder' );?></h2>
            <p class="cozmoslabs-description"><?php esc_html_e( 'Features that give you more control over your users, increased security and help you fight user registration spam.', 'profile-builder' ); ?></p>
            <a href="admin.php?page=profile-builder-general-settings" class="button button-secondary"><?php esc_html_e( 'Enable extra features', 'profile-builder' ); ?></a>

            <div id="basic-info-extra-features-list">
                <div class="cozmoslabs-form-field-wrapper">
                    <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Recover Password', 'profile-builder' ); ?></label>
                    <p class="cozmoslabs-description cozmoslabs-description-align-right"><?php printf( esc_html__( 'Allow users to recover their password in the front-end using the %s.', 'profile-builder' ), '<strong class="nowrap">[wppb-recover-password]</strong>' ); ?></p>
                </div>

                <div class="cozmoslabs-form-field-wrapper" id="basic-info-admin-approval">
                    <label class="cozmoslabs-form-field-label">
                        <?php esc_html_e( 'Admin Approval', 'profile-builder' ); ?>

                        <?php if ($version == 'Free'){ ?>
                            <span class="cozmoslabs-version-notice cozmoslabs-description-upsell"><?php printf( esc_html__( 'Only available in %1$s BASIC & PRO %2$s versions', 'profile-builder' ) ,'<a href="https://www.cozmoslabs.com/wordpress-profile-builder/?utm_source=wpbackend&utm_medium=clientsite&utm_content=basicinfo-extranotes&utm_campaign=PB'.esc_attr( $version ).'#pricing" target="_blank">', '</a>' );?></span>
                        <?php } ?>
                    </label>
                    <p class="cozmoslabs-description cozmoslabs-description-align-right"><?php esc_html_e( 'You decide who is a user on your website. Get notified via email or approve multiple users at once from the WordPress UI.', 'profile-builder' ); ?></p>
                </div>

                <div class="cozmoslabs-form-field-wrapper">
                    <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Email Confirmation', 'profile-builder' ); ?></label>
                    <p class="cozmoslabs-description cozmoslabs-description-align-right"><?php esc_html_e( 'Make sure users sign up with genuine emails. On registration users will receive a notification to confirm their email address.', 'profile-builder' ); ?></p>
                </div>

                <div class="cozmoslabs-form-field-wrapper">
                    <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Content Restriction', 'profile-builder' ); ?></label>
                    <p class="cozmoslabs-description cozmoslabs-description-align-right"><?php esc_html_e( 'Restrict users from accessing certain pages, posts or custom post types based on user role or logged-in status.', 'profile-builder' ); ?></p>
                </div>

                <div class="cozmoslabs-form-field-wrapper">
                    <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Email Customizer', 'profile-builder' ); ?></label>
                    <p class="cozmoslabs-description cozmoslabs-description-align-right"><?php esc_html_e( 'Personalize all emails sent to your users or admins. On registration, email confirmation, admin approval / un-approval.', 'profile-builder' ); ?></p>
                </div>

                <div class="cozmoslabs-form-field-wrapper">
                    <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Minimum Password Length and Strength Meter', 'profile-builder' ); ?></label>
                    <p class="cozmoslabs-description cozmoslabs-description-align-right"><?php esc_html_e( 'Eliminate weak passwords altogether by setting a minimum password length and enforcing a certain password strength.', 'profile-builder' ); ?></p>
                </div>

                <div class="cozmoslabs-form-field-wrapper">
                    <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Login with Email or Username', 'profile-builder' ); ?></label>
                    <p class="cozmoslabs-description cozmoslabs-description-align-right"><?php esc_html_e( 'Allow users to log in with their email or username when accessing your site.', 'profile-builder' ); ?></p>
                </div>

                <div class="cozmoslabs-form-field-wrapper">
                    <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Roles Editor', 'profile-builder' ); ?></label>
                    <p class="cozmoslabs-description cozmoslabs-description-align-right"><?php esc_html_e( 'Add, remove, clone and edit roles and also capabilities for these roles.', 'profile-builder' ); ?></p>
                </div>
            </div>
        </div>

		<?php
		// Output here the Extra Features html for the Free version
		$extra_features_html = ob_get_contents();
		ob_end_clean();
		if ( $version == 'Free' ) echo $extra_features_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>


		<div class="cozmoslabs-form-subsection-wrapper" id="basic-info-customize-forms">
            <h2 class="cozmoslabs-subsection-title">
                <?php esc_html_e( 'Customize Your Forms The Way You Want', 'profile-builder' ); ?>

                <?php if ($version == 'Free'){ ?>
                    <span class="cozmoslabs-version-notice cozmoslabs-description-upsell"><?php printf( esc_html__( 'Only available in %1$s BASIC & PRO %2$s versions', 'profile-builder' ) ,'<a href="https://www.cozmoslabs.com/wordpress-profile-builder/?utm_source=wpbackend&utm_medium=clientsite&utm_content=basicinfo-extranotes&utm_campaign=PB'.esc_attr( $version ).'#pricing" target="_blank">', '</a>' );?></span>
                <?php } ?>
            </h2>
            <p class="cozmoslabs-description"><?php esc_html_e( 'With Extra Profile Fields you can create the exact Registration Form your project needs.', 'profile-builder' ); ?></p>

            <?php if ($version == 'Free'){ ?>
                <a href="https://www.cozmoslabs.com/wordpress-profile-builder/?utm_source=wpbackend&utm_medium=clientsite&utm_content=basicinfo-extrafields&utm_campaign=PBFree#pricing" target="_blank" class="button button-primary wppb-button-free"><?php esc_html_e( 'Extra Profile Fields are available in Basic or PRO versions', 'profile-builder' ); ?></a>
            <?php } else {?>
                <a href="admin.php?page=manage-fields" class="button button-secondary"><?php esc_html_e( 'Get started with extra fields', 'profile-builder' ); ?></a>
            <?php } ?>

			<div class="cozmoslabs-form-field-wrapper" id="basic-info-extra-fields-list">
                <ul>
                    <li><?php esc_html_e( 'Generic Uploads', 'profile-builder' ); ?></li>
                    <li><?php esc_html_e( 'Agree To Terms', 'profile-builder' ); ?></li>
                    <li><?php esc_html_e( 'Datepicker', 'profile-builder' ); ?> </li>
                    <li><?php esc_html_e( 'Timepicker', 'profile-builder' ); ?> </li>
                    <li><?php esc_html_e( 'Colorpicker', 'profile-builder' ); ?> </li>
                    <li><?php esc_html_e( 'Country Select', 'profile-builder' ); ?></li>
                    <li><?php esc_html_e( 'Currency Select', 'profile-builder' ); ?></li>
                    <li><?php esc_html_e( 'Timezone Select', 'profile-builder' ); ?></li>
                    <li><?php esc_html_e( 'Map', 'profile-builder' ); ?></li>
                    <li><?php esc_html_e( 'Select 2 (Multiple)', 'profile-builder' ); ?></li>
                    <li><?php esc_html_e( 'Phone', 'profile-builder' ); ?></li>
                    <li><?php esc_html_e( 'Hidden Input', 'profile-builder' ); ?></li>
                    <li><?php esc_html_e( 'Number', 'profile-builder' ); ?></li>
                    <li><?php esc_html_e( 'Validation', 'profile-builder' ); ?></li>
                    <li><?php esc_html_e( 'Select CPT', 'profile-builder' ); ?></li>
                    <li><?php esc_html_e( 'HTML', 'profile-builder' ); ?></li>
                </ul>

                <img src="<?php echo esc_url( WPPB_PLUGIN_URL ); ?>assets/images/pb_fields.png" alt="Profile Builder Extra Fields" class="wppb-fields-image" />
			</div>
		</div>

        <div class="cozmoslabs-form-subsection-wrapper" id="basic-info-add-ons">
            <h2 class="cozmoslabs-subsection-title">
                <?php esc_html_e( 'Powerful Add-ons', 'profile-builder' );?>

                <?php if ($version == 'Free'){ ?>
                    <span class="cozmoslabs-version-notice cozmoslabs-description-upsell"><?php printf( esc_html__( 'Only available in %1$s PRO %2$s version', 'profile-builder' ), '<a href="https://www.cozmoslabs.com/wordpress-profile-builder/?utm_source=wpbackend&utm_medium=clientsite&utm_content=basicinfo-extranotes&utm_campaign=PB'.esc_attr( $version ).'#pricing" target="_blank">', '</a>' );?></span>
                <?php } ?>
            </h2>
            <p class="cozmoslabs-description"><?php esc_html_e( 'Everything you will need to manage your users is probably already available using the Pro Add-ons.', 'profile-builder' ); ?></p>

            <?php if( defined('WPPB_PAID_PLUGIN_DIR') && file_exists ( WPPB_PAID_PLUGIN_DIR.'/add-ons/add-ons.php' ) ): ?>
                <a href="admin.php?page=profile-builder-add-ons" class="button button-secondary"><?php esc_html_e( 'Enable your add-ons', 'profile-builder' ); ?></a>
            <?php endif; ?>
            <?php if ($version == 'Free'){ ?>
                <a href="https://www.cozmoslabs.com/wordpress-profile-builder/?utm_source=wpbackend&utm_medium=clientsite&utm_content=basicinfo-add-ons&utm_campaign=PBFree#pricing" target="_blank" class="button button-primary wppb-button-free"><?php esc_html_e( 'Find out more about PRO Modules', 'profile-builder' ); ?></a>
            <?php }?>

            <div id="basic-info-addons-list">
                <div class="cozmoslabs-form-field-wrapper">
                    <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'User Listing', 'profile-builder' ); ?></label>

                    <?php if ($version == 'Free'): ?>
                        <p class="cozmoslabs-description cozmoslabs-description-align-right"><?php esc_html_e( 'Easy to edit templates for listing your website users as well as creating single user pages. Shortcode based, offering many options to customize your listings.', 'profile-builder' ); ?></p>
                    <?php else : ?>
                        <p class="cozmoslabs-description cozmoslabs-description-align-right"><?php esc_html_e( 'Display your users in the frontend of your website, and customize how they are presented according to your preferences.', 'profile-builder' ); ?></p>
                    <?php endif;?>
                </div>

                <div class="cozmoslabs-form-field-wrapper">
                    <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Custom Redirects', 'profile-builder' ); ?></label>
                    <p class="cozmoslabs-description cozmoslabs-description-align-right"><?php esc_html_e( 'Keep your users out of the WordPress dashboard, redirect them to the front-page after login or registration, everything is just a few clicks away.', 'profile-builder' ); ?></p>
                </div>

                <div class="cozmoslabs-form-field-wrapper">
                    <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Multiple Registration Forms', 'profile-builder' ); ?></label>
                    <p class="cozmoslabs-description cozmoslabs-description-align-right"><?php esc_html_e( 'Set up multiple registration forms with different fields for certain user roles. Capture different information from different types of users.', 'profile-builder' ); ?></p>
                </div>

                <div class="cozmoslabs-form-field-wrapper">
                    <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Multiple Edit-profile Forms', 'profile-builder' ); ?></label>
                    <p class="cozmoslabs-description cozmoslabs-description-align-right"><?php esc_html_e( 'Allow different user roles to edit their specific information. Set up multiple edit-profile forms with different fields for certain user roles.', 'profile-builder' ); ?></p>
                </div>

                <div class="cozmoslabs-form-field-wrapper">
                    <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Repeater Fields', 'profile-builder' ); ?></label>
                    <p class="cozmoslabs-description cozmoslabs-description-align-right"><?php esc_html_e( 'Set up a repeating group of fields on register and edit profile forms. Limit the number of repeated groups for each user role.', 'profile-builder' ); ?></p>
                </div>
            </div>
        </div>

		<?php
		//Output here Extra Features html for Hobbyist or Pro versions
		if ( $version != 'Free' ) echo $extra_features_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>



        <div class="cozmoslabs-form-subsection-wrapper" id="basic-info-recommended-plugins">
            <h2 class="cozmoslabs-subsection-title"><?php esc_html_e( 'Recommended Plugins', 'profile-builder' );?></h2>

            <div class="cozmoslabs-basic-info-recommended" id="wppb-recommended-pms">
                <div class="cozmoslabs-basic-info-recommended-img">
                    <a href="https://wordpress.org/plugins/paid-member-subscriptions/" target="_blank"><img src="<?php echo esc_url( plugins_url( '../assets/images/pb-pms-cross-promotion.png', __FILE__ ) ); ?>" alt="paid member subscriptions"/></a>
                </div>

                <div class="cozmoslabs-basic-info-recommended-info">
                    <div class="cozmoslabs-form-field-wrapper">
                        <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Paid user profiles with Profile Builder and Paid Member Subscriptions', 'profile-builder' ); ?></label>
                    </div>

                    <p class="cozmoslabs-description"><?php esc_html_e( 'One of the most requested features in Profile Builder was for users to be able to pay for an account.', 'profile-builder' ); ?></p>
                    <p class="cozmoslabs-description"><?php esc_html_e( 'Now that is possible using the free WordPress plugin - ', 'profile-builder' ); ?> <a href="https://wordpress.org/plugins/paid-member-subscriptions/" target="_blank">Paid Member Subscriptions</a></p>
                    <a href="https://wordpress.org/plugins/paid-member-subscriptions/" class="button button-secondary" target="_blank">Find out how</a>
                </div>
            </div>

            <div class="cozmoslabs-basic-info-recommended" id="wppb-recommended-translate-press">
                <div class="cozmoslabs-basic-info-recommended-img">
                    <a href="https://wordpress.org/plugins/translatepress-multilingual/" target="_blank"><img src="<?php echo esc_url( plugins_url( '../assets/images/pb-trp-cross-promotion.svg', __FILE__ ) ); ?>" alt="TranslatePress Logo"/></a>
                </div>

                <div class="cozmoslabs-basic-info-recommended-info">
                    <div class="cozmoslabs-form-field-wrapper">
                        <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Easily translate your entire WordPress website', 'profile-builder' ); ?></label>
                    </div>

                    <p class="cozmoslabs-description"><?php esc_html_e( 'Translate your Profile Builder forms with a WordPress translation plugin that anyone can use.', 'profile-builder' ); ?></p>
                    <p class="cozmoslabs-description"><?php esc_html_e( 'It offers a simpler way to translate WordPress sites, with full support for WooCommerce and site builders.', 'profile-builder' ); ?></p>
                    <a href="https://wordpress.org/plugins/translatepress-multilingual/" class="button button-secondary" target="_blank">Find out how</a>
                </div>
            </div>

            <div class="cozmoslabs-basic-info-recommended" id="wppb-recommended-wp-webhooks">
                <div class="cozmoslabs-basic-info-recommended-img">
                    <a href="https://wordpress.org/plugins/translatepress-multilingual/" target="_blank"><img src="<?php echo esc_url( plugins_url( '../assets/images/wp-webhooks-banner.svg', __FILE__ ) ); ?>" alt="TranslatePress Logo"/></a>
                </div>

                <div class="cozmoslabs-basic-info-recommended-info">
                    <div class="cozmoslabs-form-field-wrapper">
                        <label class="cozmoslabs-form-field-label"><?php esc_html_e( 'Save time and money using automations', 'profile-builder' ); ?></label>
                    </div>

                    <p class="cozmoslabs-description"><?php esc_html_e( 'Create no-code automations and workflows on your WordPress site.', 'profile-builder' ); ?></p>
                    <p class="cozmoslabs-description"><?php esc_html_e( 'Integrates with Profile Builder or Paid Member Subscriptions, depending on which plugin it\'s for.', 'profile-builder' ); ?></p>
                    <a href="https://www.wp-webhooks.com/?utm_source=wpbackend&utm_medium=clientsite&utm_content=add-on-page&utm_campaign=PBPro" class="button button-secondary" target="_blank">Find out how</a>
                </div>
            </div>

        </div>

	</div>
<?php
}