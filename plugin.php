<?php
/**
 * Plugin Name: Secure WP-API
 * Plugin URI: http://www.liangeugene.com
 * Description: This plugin makes sure that all WP-API endpoints requires an access token. This plugin is dependent on wp-oauth.com
 * Version: 1.0.0
 * Author: Eugene Liang
 * Author URI: http://www.liangeugene.com
 * License: GPL2
 */


// need to avoid the login function.
function checkForAccessToken( $result ) {
    $incoming = $_SERVER['HTTP_REFERER'];
    $allowedURL = "/oauth/token";
    $pos = strpos($incoming, $allowedURL);
    if ($pos === true) {
        return; // simply continue;
    }



    if ($_SERVER['REQUEST_METHOD'] == 'GET') {
        $access_token = $_GET['access_token'];
        if (!$access_token) {
            // if there's not even a token, we should just deny access
            return new WP_Error( 'access_denied', __( 'Access denied, you need an access token', 'text_domain' ), array( 'status' => 403 ) );
        }
        else {
            // just continue. so in theory, we need to see if there's a valid token.
            /*
                firstly, check if there's a token. since there is....

                1) check if the access_token is within the table

                2) if 1 is true, check the user's role. if
                - admin can read everything ?

                3) for POST/DELETE stuff, it's already checked by the current WP-API

                // check for token in table

            */
            global $wpdb;
            //$myrows = $wpdb->get_results( "SELECT * FROM wp_oauth_access_token WHERE access_token" );

            // check for it first, than check for expiry....
            $query = $wpdb->prepare(
            	"
            		SELECT *
            		FROM wp_oauth_access_tokens
            		WHERE access_token = %s
            	",
            	$access_token
            );
            $myrows = $wpdb->get_row($query);
            if (!$myrows) {
                return new WP_Error( 'access_denied', __( 'Access denied, you need a valid access token', 'text_domain' ), array( 'status' => 403 ) );
            }
            else {
                // check for expiry
                $nowTime = strtotime("now");//date('Y-m-d H:i:s');
                $answer = $nowTime - strtotime($myrows->expires);

                $answer2 = strtotime($myrows->expires) - $nowTime;

                // if not expired, than go ahead.
                if (($nowTime - strtotime($myrows->expires)) > 0) {
                    // expired
                    return new WP_Error( 'access_denied', __( 'Access denied, your token expired', 'text_domain' ), array( 'status' => 403 ) );
                }
                else {
                    // not expired, and at least there's a working token.
                    return $result;
                }
            }
            return $result;
        }

    }

}
//add_filter('rest_authentication_errors', 'checkForAccessToken');
add_filter('rest_pre_dispatch', 'checkForAccessToken');
