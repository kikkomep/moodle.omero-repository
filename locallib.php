<?php

// Copyright (c) 2015-2016, CRS4
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

defined('MOODLE_INTERNAL') || die();
require_once($CFG->libdir . '/oauthlib.php');


/**
 * Class confidential_oauth2_client,
 * an helper class to handle OAuth request
 * from a confidential OAuth client.
 */
class confidential_oauth2_client extends oauth2_client
{
    private $disable_login_check = false;

    protected function enable_authorization($enabled = true)
    {
        $this->disable_login_check = !$enabled;
    }

    /**
     * Returns the auth url for OAuth 2.0 request
     * @return string the auth url
     */
    protected function auth_url()
    {
        return "http://mep.crs4.it:8000/o/authorize/"; // FIXME: remove me: it's just for debugging!
        return get_config('omero', 'omero_restendpoint') . "/o/authorize/";
    }

    /**
     * Returns the token url for OAuth 2.0 request
     * @return string the auth url
     */
    protected function token_url()
    {
        return "http://mep.crs4.it:8000/o/token/"; // FIXME: remove me: it's just for debugging!
        return get_config('omero', 'omero_restendpoint') . "/o/token/";
    }

    /**
     * Is the user logged in? Note that if this is called
     * after the first part of the authorisation flow the token
     * is upgraded to an accesstoken.
     *
     * @return boolean true if logged in
     */
    public function is_logged_in() {
        // Has the token expired?
        $token = $this->get_accesstoken();
//        debugging("Expired: " .
//        (isset($token->expires) && time() >= $token->expires)
//            ? "NO" : "YES"
//        );
        if (isset($token->expires) && time() >= $token->expires) {
            $this->log_out();
            return false;
        }

        // We have a token so we are logged in.
        if (isset($token->token)) {
            return true;
        }

        // This kind of client doesn't support authorization code
        return false;
    }

    /**
     * @param bool $refresh
     * @return bool
     * @throws moodle_exception
     */
    public function upgrade_token($refresh = false)
    {
        $token = null;
        if (!$this->disable_login_check && (!$this->get_stored_token() || $refresh)) {

            //debugging("Token not found in cache");

            $this->disable_login_check = true;

            $params = array(
                'client_id' => $this->get_clientid(),
                'client_secret' => $this->get_clientsecret(),
                'grant_type' => 'client_credentials'
            );

            // clear the current token
            $this->store_token(null);

            // retrieve a new token
            $response = $this->post($this->token_url(), $params);
            $token = json_decode($response);

            // register the new token
            if ($token && isset($token->access_token)) {
                //debugging("retrieved token: " . json_encode($token));
                $token->token = $token->access_token;
                $token->expires = (time() + ($token->expires_in - 10)); // Expires 10 seconds before actual expiry.
                $this->store_token($token);
                //debugging("Type of retrieve object: " . gettype($token));
                return true;
            } else {
                //debugging("Unable to retrieve the authentication token");
                error("Authentication Error !!!");
            }

            $this->disable_login_check = false;

        } else {
            $token = $this->get_stored_token();
            //debugging("Token is in SESSION");
            //debugging("Type of token object: " . gettype($token));
            return true;
        }

        return false;
    }


    /**
     * Refresh the current token
     */
    protected function refresh_access_token()
    {
        $this->upgrade_token(true);
    }

    /**
     * Process a request adding the required OAuth token
     *
     * @param string $url
     * @param array $options
     * @return bool
     */
    protected function request($url, $options = array())
    {
        if (!$this->disable_login_check) {
            //debugging("Is LOGGED: " . ($this->is_logged_in() ? "YES" : "NO"));
            if (!$this->is_logged_in()) {
                if ($this->upgrade_token(false)) {
                    //debugging("New TOKEN: " . json_encode($this->get_accesstoken()));
                }
            } else {
                //debugging("Old TOKEN: " . json_encode($this->get_accesstoken()));
            }
        }
        return parent::request($url, $options);
    }
}


/**
 * A helper class to access omero resources
 *
 * @since      Moodle 2.0
 * @package    repository_omero
 * @copyright  2015-2016 CRS4
 * @license    https://opensource.org/licenses/mit-license.php MIT license
 */
class omero extends confidential_oauth2_client
{
    /** @var string omero access type, can be omero or sandbox */
    private $mode = 'omero';
    /** @var string omero api url */
    private $omero_api;
    /** @var string omero content api url */
    private $omero_content_api;


    /**
     * Constructor for omero class
     *
     * @param string $client_id
     * @param string $client_secret
     * @param moodle_url $moodle_url
     * @param string $scope
     * @throws dml_exception
     * @internal param array $options
     */
    public function __construct($client_id, $client_secret, moodle_url $moodle_url, $scope = "read")
    {
        parent::__construct($client_id, $client_secret, $moodle_url, $scope);
        $this->omero_api = get_config('omero', 'omero_restendpoint');
    }

    /**
     * Returns the configuration merging default values with client definded
     * @param $options
     * @return array
     * @throws dml_exception
     */
    private function get_config($options)
    {
        // TODO: update the default settings
        return array_merge(array(
            "oauth_consumer_key" => get_config('omero', "omero_key"),
            "oauth_consumer_secret" => get_config('omero', "omero_secret"),
            "access_token" => "omero",
            "access_token_secret" => "omero"
        ), $options);
    }

    /**
     * Process request
     *
     * @param string $path
     * @param bool $decode
     * @param string $token
     * @param string $secret
     * @return mixed
     */
    public function process_request($path = '/', $decode = true, $token = '', $secret = '')
    {
        //debugging("PROCESSING REQUEST: $path - decode: $decode");
        $url = $this->omero_api . "/ome_seadragon" . $path;
        $response = $this->get($url, array(), $token, $secret);
        $result = $decode ? json_decode($response) : $response;
        //debugging("PROCESSING REQUEST OK");
        return $result;
    }


    /**
     * @param $search_text
     * @param string $token
     * @param string $secret
     * @return mixed
     */
    public function process_search($search_text, $token = '', $secret = '')
    {
        $url = $this->omero_api . "/ome_seadragon" . PathUtils::build_find_annotations_url($search_text);
        $content = $this->get($url, array(), $token, $secret);
        $data = json_decode($content);
        return $data;
    }

    /**
     * Prepares the filename to pass to omero API as part of URL
     *
     * @param string $filepath
     * @return string
     */
    protected function prepare_filepath($filepath)
    {
        $info = pathinfo($filepath);
        $dirname = $info['dirname'];
        $basename = $info['basename'];
        $filepath = $dirname . rawurlencode($basename);
        if ($dirname != '/') {
            $filepath = $dirname . '/' . $basename;
            $filepath = str_replace("%2F", "/", rawurlencode($filepath));
        }
        return $filepath;
    }

    /**
     * Retrieves the default (64x64) thumbnail for omero file
     *
     * @throws moodle_exception when file could not be downloaded
     *
     * @param string $filepath local path in omero
     * @param string $saveas path to file to save the result
     * @param int $timeout request timeout in seconds, 0 means no timeout
     * @return array with attributes 'path' and 'url'
     */
    public function get_thumbnail($filepath, $saveas, $timeout = 0)
    {
        $url = $this->omero_api . '/thumbnails/' . $this->mode . $this->prepare_filepath($filepath);
        if (!($fp = fopen($saveas, 'w'))) {
            throw new moodle_exception('cannotwritefile', 'error', '', $saveas);
        }
        $this->setup_oauth_http_options(array('timeout' => $timeout, 'file' => $fp, 'BINARYTRANSFER' => true));
        $result = $this->get($url);
        fclose($fp);
        if ($result === true) {
            return array('path' => $saveas, 'url' => $url);
        } else {
            unlink($saveas);
            throw new moodle_exception('errorwhiledownload', 'repository', '', $result);
        }
    }


    /**
     * Downloads a file from omero and saves it locally
     *
     * @throws moodle_exception when file could not be downloaded
     *
     * @param string $filepath local path in omero
     * @param string $saveas path to file to save the result
     * @param int $timeout request timeout in seconds, 0 means no timeout
     * @return array with attributes 'path' and 'url'
     */
    public function get_file($filepath, $saveas, $timeout = 0)
    {
        $url = $this->omero_api . '/files/' . $this->mode . $this->prepare_filepath($filepath);
        if (!($fp = fopen($saveas, 'w'))) {
            throw new moodle_exception('cannotwritefile', 'error', '', $saveas);
        }
        $this->setup_oauth_http_options(array('timeout' => $timeout, 'file' => $fp, 'BINARYTRANSFER' => true));
        $result = $this->get($url);
        fclose($fp);
        if ($result === true) {
            return array('path' => $saveas, 'url' => $url);
        } else {
            unlink($saveas);
            throw new moodle_exception('errorwhiledownload', 'repository', '', $result);
        }
    }

    /**
     * Returns direct link to omero file
     *
     * @param string $filepath local path in omero
     * @param int $timeout request timeout in seconds, 0 means no timeout
     * @return string|null information object or null if request failed with an error
     */
    public function get_file_share_link($filepath, $timeout = 0)
    {
        $url = $this->omero_api . '/shares/' . $this->mode . $this->prepare_filepath($filepath);
        $this->setup_oauth_http_options(array('timeout' => $timeout));
        $result = $this->post($url, array('short_url' => 0));
        if (!$this->http->get_errno()) {
            $data = json_decode($result);
            if (isset($data->url)) {
                return $data->url;
            }
        }
        return null;
    }

    /**
     * Sets omero API mode (omero or sandbox, default omero)
     *
     * @param string $mode
     */
    public function set_mode($mode)
    {
        $this->mode = $mode;
    }
}


/**
 * Utility class for building REST Api url
 */
class PathUtils
{

    public static function is_root_path($path)
    {
        return !strcmp($path, "/");
    }

    public static function is_projects_root($path)
    {
        return preg_match("/get\/projects/", $path);
    }

    public static function is_annotations_root($path)
    {
        return preg_match("/get\/annotations/", $path);
    }

    public static function is_tagset_root($path)
    {
        return preg_match("/get\/tagset\/(\d+)/", $path);
    }

    public static function is_tag($path)
    {
        return preg_match("/get\/tag\/(\d+)/", $path);
    }

    public static function is_project($path)
    {
        return preg_match("/get\/project\/(\d+)/", $path);
    }

    public static function is_dataset($path)
    {
        return preg_match("/get\/dataset\/(\d+)/", $path);
    }

    public static function is_image_file($path)
    {
        return preg_match("/get\/image/\/(\d+)/", $path);
    }

    public static function is_annotations_query($path)
    {
        return preg_match("/find\/annotations/", $path);
    }

    public static function build_project_list_url()
    {
        return "/get/projects";
    }

    public static function build_annotation_list_url()
    {
        return "/get/annotations";
    }

    public static function build_find_annotations_url($query)
    {
        return "/find/annotations?query=$query";
    }

    public static function build_tagset_deatails_url($tagset_id, $tags = true)
    {
        return "/get/tagset/$tagset_id?tags=$tags";
    }

    public static function build_tag_detail_url($tag_id)
    {
        return "/get/tag/$tag_id?images=true";
    }

    public static function build_project_detail_url($project_id)
    {
        return "/get/project/$project_id";
    }

    public static function build_dataset_list_url($project_id, $datasets = true)
    {
        return "/get/project/$project_id?datasets=$datasets";
    }

    public static function build_dataset_detail_url($dataset_id, $images = true)
    {
        return "/get/dataset/$dataset_id?images=$images";
    }

    public static function build_image_detail_url($image_id, $rois = true)
    {
        return "/get/image/$image_id?rois=$rois";
    }

    public static function build_image_dzi_url($image_id)
    {
        return "/deepzoom/image_mpp/${image_id}.dzi";
    }

    public static function build_image_thumbnail_url($image_id, $lastUpdate, $height = 128, $width = 128)
    {
        global $CFG;
        return "$CFG->wwwroot/repository/omero/thumbnail.php?id=$image_id&lastUpdate=$lastUpdate&height=$height&width=$width";
    }

    public static function get_element_id_from_url($url, $element_name)
    {
        if (preg_match("/$element_name\/(\d+)/", $url, $matches))
            return $matches[1];
        return null;
    }
}

/**
 * omero plugin cron task
 */
function repository_omero_cron()
{
    $instances = repository::get_instances(array('type' => 'omero'));
    foreach ($instances as $instance) {
        $instance->cron();
    }
}