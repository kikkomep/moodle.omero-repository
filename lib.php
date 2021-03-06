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

require_once($CFG->dirroot . '/repository/lib.php');
require_once(dirname(__FILE__) . '/locallib.php');

/**
 * This plugin is used to access user's omero files
 *
 * @since      Moodle 2.0
 * @package    repository_omero
 * @copyright  2015-2016 CRS4
 * @license    https://opensource.org/licenses/mit-license.php MIT license
 */
class repository_omero extends repository
{
    /** @var OmeroImageRepository the instance of omero client */
    private $omero;

    /** @var cache_session */
    private $requests;

    /** @var array files */
    public $files;

    /** @var bool flag of login status */
    public $logged = false;

    /** @var int maximum size of file to cache in moodle filepool */
    public $cachelimit = null;

    /** @var int cached file ttl */
    private $cachedfilettl = null;

    /** projects and datasets filter */
    private $item_black_list = array(
        "Atlante", "Melanomi e nevi", "slide_seminar_CAAP2015",
        "2015-08-11", "TEST"
    );

    /** @var bool enable/disable pagination */
    private $ENABLE_PAGINATION = false;

    /** @var array Projects root */
    private $PROJECTS_ROOT_ITEM = array(
        "id" => "0",
        "name" => "projects",
        "type" => "projects",
        "path" => "/projects"
    );

    /** @var array Tagsets root */
    private $TAGS_ROOT_ITEM = array(
        "id" => "0",
        "name" => "tags",
        "type" => "tags",
        "path" => "/tags"
    );

    /** @var array Defines the set of supported API versions */
    public static $API_VERSIONS = array(
        "OmeSeadragonImageRepository" => "OmeSeadragon API",
        "OmeSeadragonGatewayImageRepository" => "OmeSeadragon Gateway API"
    );

    // Session keys
    const OMERO_TAGSET_KEY = "omero_tagset";
    const OMERO_PROJECT_KEY = "omero_project";
    const OMERO_DATASET_KEY = "omero_dataset";
    const OMERO_ANNOTATION_QUERY_KEY = "omero_annotation_query";
    const OMERO_LAST_QUERY_KEY = "omero_last_query_key";


    /**
     * Constructor of omero plugin
     *
     * @param int $repositoryid
     * @param bool|int|stdClass $context
     * @param array $options
     * @throws coding_exception
     */
    public function __construct($repositoryid, $context = SYSCONTEXTID, $options = array())
    {
        global $CFG;
        $options['page'] = optional_param('p', 1, PARAM_INT);
        parent::__construct($repositoryid, $context, $options);

        $this->setting = 'omero_';

        $this->omero_restendpoint = $this->get_option('omero_restendpoint');
        $this->omero_key = $this->get_option('omero_key');
        $this->omero_secret = $this->get_option('omero_secret');

        // one day
        $this->cachedfilettl = 60 * 60 * 24;

        if (isset($options['omero_restendpoint'])) {
            $this->omero_restendpoint = $options['omero_restendpoint'];
        } else {
            $this->omero_restendpoint = get_user_preferences($this->setting . '_omero_restendpoint', '');
        }
        if (isset($options['access_key'])) {
            $this->access_key = $options['access_key'];
        } else {
            $this->access_key = get_user_preferences($this->setting . '_access_key', '');
        }
        if (isset($options['access_secret'])) {
            $this->access_secret = $options['access_secret'];
        } else {
            $this->access_secret = get_user_preferences($this->setting . '_access_secret', '');
        }

        if (!empty($this->access_key) && !empty($this->access_secret)) {
            $this->logged = true;
        }

        $callbackurl = new moodle_url($CFG->wwwroot . '/repository/repository_callback.php', array(
            'callback' => 'yes',
            'repo_id' => $repositoryid
        ));

        $toprint = "";
        foreach ($options as $k => $v) {
            $toprint .= $k;
        }

        $args = array(
            'omero_restendpoint' => $this->omero_restendpoint,
            'oauth_consumer_key' => $this->omero_key,
            'oauth_consumer_secret' => $this->omero_secret,
            'oauth_callback' => $callbackurl->out(false),
            'api_root' => $this->omero_restendpoint,
        );

        // instantiate the omero client
        $this->omero = OmeroImageRepository::get_instance($args);

        // set cache references
        $this->requests = cache::make('repository_omero', 'repository_info_cache');
    }

    /**
     * Set access key
     *
     * @param string $access_key
     */
    public function set_access_key($access_key)
    {
        $this->access_key = $access_key;
    }

    /**
     * Set access secret
     *
     * @param string $access_secret
     */
    public function set_access_secret($access_secret)
    {
        $this->access_secret = $access_secret;
    }


    /**
     * Check if moodle has got access token and secret
     *
     * @return bool
     */
    public function check_login()
    {
        //return !empty($this->logged);
        return true; // disabled plugin loigin
    }

    /**
     * Generate omero login url
     *
     * @return array
     */
    public function print_login()
    {
        $result = $this->omero->request_token();
        set_user_preference($this->setting . '_request_secret', $result['oauth_token_secret']);
        $url = $result['authorize_url'];
        if ($this->options['ajax']) {
            $ret = array();
            $popup_btn = new stdClass();
            $popup_btn->type = 'popup';
            $popup_btn->url = $url;
            $ret['login'] = array($popup_btn);
            return $ret;
        } else {
            echo '<a target="_blank" href="' . $url . '">' . get_string('login', 'repository') . '</a>';
        }
    }

    /**
     * Request access token
     *
     * @return array
     */
    public function callback()
    {
        $token = optional_param('oauth_token', '', PARAM_TEXT);
        $secret = get_user_preferences($this->setting . '_request_secret', '');
        $access_token = $this->omero->get_access_token($token, $secret);
        set_user_preference($this->setting . '_access_key', $access_token['oauth_token']);
        set_user_preference($this->setting . '_access_secret', $access_token['oauth_token_secret']);
    }

    /**
     * Get omero files
     *
     * @param string $path
     * @param int|string $page
     * @param null $search_text
     * @return array
     */
    public function get_listing($path = '/', $page = '1', $search_text = null)
    {
        global $CFG, $OUTPUT;

        // shortcut to the API urls
        $urls = $this->omero->URLS;

        // format the current selected URL
        if (empty($path)) {
            $path = '/';
        }

        // Initializes the data structures needed to build the response
        $list = array();
        $list['list'] = array();
        $list['manage'] = get_config('omero', 'omero_webclient');
        $list['dynload'] = true;
        $list['nologin'] = true;
        $list['search_query'] = $search_text;

        // Host the navigation links
        $navigation_list = array();

        // Enable/Disable the search field
        $list['nosearch'] = false;

        // process search request
        if (isset($search_text) || $urls->is_annotations_query_url($path)) {
            if (isset($search_text))
                $response = $this->omero->find_annotations($search_text);
            else $response = $this->process_request($path);

            foreach ($response as $item) {
                $itype = "Tag";
                if (strcmp($item->type, "tagset") == 0)
                    $itype = "TagSet";
                $obj = $this->process_list_item($itype, $item);
                if ($obj != null)
                    $list['list'][] = $obj;
            }

            // Set this result as a search result
            $list['issearchresult'] = true;

            // Build the navigation bar
            $list['path'] = $this->build_navigation_bar($navigation_list, "/find/annotations", "", $search_text);

        } else {

            // true if the list is a search result
            $list['issearchresult'] = false;


            if ($urls->is_root_url($path)) {
                debugging("Is Root");
                $list['list'][] = $this->process_list_item("ProjectRoot", (object)$this->PROJECTS_ROOT_ITEM);
                $list['list'][] = $this->process_list_item("TagRoot", (object)$this->TAGS_ROOT_ITEM);
                // Build the navigation bar
                $list['path'] = $this->build_navigation_bar($navigation_list, $path);

            } else if ($urls->is_projects_url($path)) {
                debugging("The root project path has been selected !!!");
                $response = $this->omero->get_projects();
                foreach ($response as $item) {
                    debugging("Processing project...");
                    $obj = $this->process_list_item("Project", $item);
                    debugging("Project.... PATH: " . $obj["path"]);
                    if ($obj != null)
                        $list['list'][] = $obj;
                }
                // Build the navigation bar
                $list['path'] = $this->build_navigation_bar($navigation_list, $path);

            } else if ($urls->is_annotations_url($path)) {
                debugging("The root tag path has been selected !!!");
                $response = $this->omero->get_annotations();
                foreach ($response as $item) {
                    $itype = "Tag";
                    if (strcmp($item->type, "tagset") == 0)
                        $itype = "TagSet";
                    $obj = $this->process_list_item($itype, $item);
                    if ($obj != null) {
                        $list['list'][] = $obj;
                    }
                }
                // Build the navigation bar
                $list['path'] = $this->build_navigation_bar($navigation_list, $path);

            } else if ($urls->is_tagset_url($path)) {
                debugging("The tagset root path has been selected: $path !!!");
                $tagset_id = $urls->get_element_id_from_url($path);
                $response = $this->omero->get_tagset($tagset_id);
                foreach ($response->tags as $item) {
                    $obj = $this->process_list_item("Tag", $item);
                    if ($obj != null) {
                        $list['list'][] = $obj;
                    }
                }
                // Build the navigation bar
                $list['path'] = $this->build_navigation_bar($navigation_list, $path, $response);

            } else {

                if ($urls->is_tag_url($path)) {
                    debugging("Tag selected: $path!!!");
                    $tag_id = $urls->get_element_id_from_url($path);
                    $selected_obj_info = $this->omero->get_tag($tag_id);
                    $response = $selected_obj_info;
                    foreach ($response->images as $item) {
                        $obj = $this->process_list_item("Image", $item);
                        if ($obj != null)
                            $list['list'][] = $obj;
                    }
                    // Build the navigation bar
                    $list['path'] = $this->build_navigation_bar($navigation_list, $path, $response);

                } else if ($urls->is_project_url($path)) {
                    debugging("Project selected: $path !!!");
                    $project_id = $urls->get_element_id_from_url($path);
                    $response = $this->omero->get_project($project_id);
                    debugging(json_encode($response));
                    if (isset($response->datasets)) {
                        foreach ($response->datasets as $item) {
                            $obj = $this->process_list_item("Dataset", $item);
                            if ($obj != null)
                                $list['list'][] = $obj;
                        }
                    }
                    // Build the navigation bar
                    $list['path'] = $this->build_navigation_bar($navigation_list, $path, $response);

                } else if ($urls->is_dataset_url($path)) {
                    debugging("Dataset selected: $path!!!");
                    $dataset_id = $urls->get_element_id_from_url($path);
                    $response = $this->omero->get_dataset($dataset_id, true);
                    // Build the navigation bar
                    $list['path'] = $this->build_navigation_bar($navigation_list, $path, $response);
                    // process images
                    if ($this->ENABLE_PAGINATION) {
                        if (empty($page))
                            $page = 1;
                        else $page = ((int)$page);
                        $num_images_per_page = 12;
                        $list['page'] = $page;
                        $list['pages'] = 1;
                        if (count($response) > 12)
                            $list['pages'] = 1 + ceil((count($response) - 12) / $num_images_per_page);
                        $last = $page == 1 ? 12 : $page * $num_images_per_page;
                        $first = $last - ($page == 1 ? 12 : $num_images_per_page);
                        $counter = 0;
                        foreach ($response as $item) {
                            if ($counter == $last) break;
                            if ($counter < $first) {
                                $counter++;
                                continue;
                            } else {
                                $processed_item = $this->process_list_item("Image", $item);
                                if ($processed_item != null) {
                                    $list['list'][] = $processed_item;
                                }
                                $counter++;
                            }
                        }

                    } else {
                        $list['pages'] = 1;
                        foreach ($response->images as $item) {
                            $processed_item = $this->process_list_item("Image", $item);
                            if ($processed_item != null) {
                                $list['list'][] = $processed_item;
                            }
                        }
                        return $list;
                    }

                } else {
                    debugging("Unknown resource selected: $path !!!: ");
                }
            }
        }

        return $list;
    }


    /**
     * Builds the navigation bar
     */
    public function build_navigation_bar($result, $path, $obj_info = null, $annotations_query = false)
    {
        debugging("BUILDING NAVIGATION BAR: $path");

        // shortcut to the API urls
        $urls = $this->omero->URLS;

        // alias for the 'requests' cache
        $cache = $this->requests;

        // get existing session objects
        $omero_tagset = $cache->get(self::OMERO_TAGSET_KEY);
        $omero_project = $cache->get(self::OMERO_PROJECT_KEY);
        if (!$annotations_query)
            $annotations_query = $cache->get(self::OMERO_ANNOTATION_QUERY_KEY);

        // clean current value sessions
        // when a new navigation path starts
        if ($this->omero->URLS->is_root_url($path) ||
            $this->omero->URLS->is_projects_url($path) ||
            $this->omero->URLS->is_annotations_url($path)
        ) {
            // invalidate current session values
            $cache->delete_many(
                array(
                    self::OMERO_ANNOTATION_QUERY_KEY,
                    self::OMERO_TAGSET_KEY,
                    self::OMERO_PROJECT_KEY,
                    self::OMERO_DATASET_KEY
                )
            );
            // invalidate the annotation_query parameter
            $annotations_query = false;
        }

        // adds the root
        array_push($result, array('name' => "/", 'path' => $urls->get_root_url()));

        // Query reference
        if ($annotations_query) {
            if ($annotations_query) {
                array_push($result, array(
                        'name' => "Query: $annotations_query",
                        'path' => $urls->get_annotations_query_url($annotations_query))
                );
                $_SESSION['$omero_search_text'] = $annotations_query;
            }
        }

        // process remaining elements by type
        if ($urls->is_annotations_url($path)) {
            if (!$annotations_query)
                array_push($result, array(
                        'name' => get_string('tags', 'repository_omero'),
                        'path' => $urls->get_annotations_url())
                );

        } else if ($urls->is_tagset_url($path)) {
            if (!$annotations_query)
                array_push($result, array(
                        'name' => get_string('tags', 'repository_omero'),
                        'path' => $urls->get_annotations_url()
                    )
                );
            array_push($result, array(
                    'name' => $this->format_navbar_element_name(
                        get_string('tagset', 'repository_omero'), $obj_info->value, $obj_info->id
                    ),
                    'path' => $urls->get_tagset_url($obj_info->id)
                )
            );
            $cache->set(self::OMERO_TAGSET_KEY, $obj_info);

        } else if ($urls->is_tag_url($path)) {
            if (!$annotations_query)
                array_push($result, array(
                        'name' => get_string('tags', 'repository_omero'),
                        'path' => $urls->get_annotations_url())
                );
            if (isset($omero_tagset) && !empty($omero_tagset)) {
                array_push($result, array(
                        'name' => $this->format_navbar_element_name(
                            get_string('tagset', 'repository_omero'), $omero_tagset->value, $omero_tagset->id
                        ),
                        'path' => $urls->get_tagset_url($omero_tagset->id)
                    )
                );
            }
            array_push($result, array(
                    'name' => $this->format_navbar_element_name(
                        get_string('tag', 'repository_omero'), $obj_info->value, $obj_info->id
                    ),
                    'path' => $path
                )
            );

        } else if ($urls->is_projects_url($path)) {
            array_push($result, array(
                    'name' => get_string('projects', 'repository_omero'),
                    'path' => $urls->get_projects_url())
            );

        } else if ($urls->is_project_url($path)) {
            $omero_project = $obj_info;
            $cache->set(self::OMERO_PROJECT_KEY, $omero_project);
            array_push($result, array(
                    'name' => get_string('projects', 'repository_omero'),
                    'path' => $urls->get_projects_url())
            );
            array_push($result, array(
                    'name' => $this->format_navbar_element_name(
                        get_string('project', 'repository_omero'), $omero_project->name, $omero_project->id
                    ),
                    'path' => $urls->get_project_url($omero_project->id))
            );

        } else if ($urls->is_dataset_url($path)) {
            $omero_dataset = $obj_info;
            $cache->set(self::OMERO_DATASET_KEY, $omero_dataset);
            array_push($result, array(
                'name' => get_string('projects', 'repository_omero'),
                'path' => $urls->get_projects_url()));
            array_push($result, array(
                    'name' => $this->format_navbar_element_name(
                        get_string('project', 'repository_omero'),
                        $omero_project->name, $omero_project->id),
                    'path' => $urls->get_project_url($omero_project->id))
            );
            array_push($result, array(
                    'name' => $this->format_navbar_element_name(
                        get_string('dataset', 'repository_omero'), $omero_dataset->name, $omero_dataset->id),
                    'path' => $urls->get_dataset_url($omero_dataset->id))
            );
        }

        return $result;
    }

    /**
     * Format the name of navigation element
     * @param $label
     * @param $name
     * @param $id
     * @return string
     */
    private function format_navbar_element_name($label, $name, $id)
    {
        return "$label: $name [id.$id]";
    }

    /**
     * Process a request (with cache support)
     *
     * @param $url
     * @return array|false|mixed
     */
    private function process_request($url)
    {
        debugging("Processing request: $url");

        // cache key
        $key = urlencode($url);

        // check whether the current path has been already selected:
        // if the 'lastPath' is equal to 'path' then the corresponding
        // cached value will be removed !!!
        if (strcmp($this->requests->get(self::OMERO_LAST_QUERY_KEY), $url) === 0) {
            $this->requests->delete($key);
            debugging("Cleaning cache: " . "$url -- " . $key);
        }

        // store the last query URL
        $this->requests->set(self::OMERO_LAST_QUERY_KEY, $url);

        // check whether the request is in cache and process it otherwise
        $response = $this->requests->get($key);
        if (!$response) {
            debugging("Getting data from the SERVER: $url");
            $response = $this->omero->process_request($url, true);
            $this->requests->set($key, $response);
            debugging("RESPONSE IS OBJECT: " . (is_object($response) ? "OK" : "NO"));
        } else debugging("Getting data from the CACHE: $url");
        return $response;
    }


    /**
     * Fill data for a list item
     *
     * @param $type
     * @param $item
     * @param null $filter
     * @return array|null
     */
    public function process_list_item($type, $item, $filter = null)
    {
        global $OUTPUT;

        // Hardwired filter to force only a subset of projects and datasets
        if (strcmp($type, "Project") == 0 || strcmp($type, "Dataset") == 0) {
            foreach ($this->item_black_list as $pattern) {
                if (preg_match("/^$pattern$/", $item->name)) {
                    return null;
                }
            }
        }

        // shortcut to the API urls
        $urls = $this->omero->URLS;

        //
        $thumbnail_height = 95;
        $thumbnail_width = 95;
        $itemObj = array(
            'image_id' => $item->id,
            'title' => "Undefined",
            'source' => $item->id,
            'license' => "unknown",
            'children' => array()
        );

        if (strcmp($type, "ProjectRoot") == 0) {
            $itemObj["title"] = get_string('projects', 'repository_omero');
            $itemObj["path"] = $urls->get_projects_url();
            $itemObj["thumbnail"] = $OUTPUT->pix_url(file_folder_icon(64))->out(true);

        } else if (strcmp($type, "TagRoot") == 0) {
            $itemObj["title"] = get_string('tags', 'repository_omero');
            $itemObj["path"] = $urls->get_annotations_url();
            $itemObj["thumbnail"] = $this->file_icon("tagset", 64);

        } else if (strcmp($type, "TagSet") == 0) {
            $itemObj["title"] = $item->value . " [id:" . $item->id . "]";
            $itemObj["path"] = $urls->get_tagset_url($item->id);
            $itemObj["thumbnail"] = $this->file_icon("tagset", 64);

        } else if (strcmp($type, "Tag") == 0) {
            $itemObj["title"] = $item->value . (!empty($item->description) ? (" " . $item->description) : "") . " [id:" . $item->id . "]";
            $itemObj["path"] = $urls->get_tag_url($item->id);
            $itemObj["thumbnail"] = $this->file_icon("tag", 64);

        } else if (strcmp($type, "Project") == 0) {
            $itemObj["title"] = $item->name . " [id:" . $item->id . "]";
            $itemObj["path"] = $urls->get_project_url($item->id);
            $itemObj["thumbnail"] = $OUTPUT->pix_url(file_folder_icon(64))->out(true);

        } else if (strcmp($type, "Dataset") == 0) {
            $itemObj["title"] = $item->name . " [id:" . $item->id . "]";
            $itemObj["path"] = $urls->get_dataset_url($item->id);
            $itemObj["thumbnail"] = $OUTPUT->pix_url(file_folder_icon(64))->out(true);

        } else if (strcmp($type, "Image") == 0) {

            // replace image ID with the ID of the higher resolution image of the series
            $image_source = isset($item->high_resolution_image) ?
                $item->high_resolution_image : $item->id;

            $image_thumbnail = $urls->get_image_thumbnail_url(
                $item->id, $item->lastUpdate, $thumbnail_height, $thumbnail_width);
            $itemObj['source'] = $image_source;
            $itemObj["title"] = $item->name . " [id:" . $image_source . "]";
            $itemObj["author"] = $item->author;
            $itemObj["path"] = $urls->get_image_url($item->id);
            $itemObj["thumbnail"] = $image_thumbnail;
            $itemObj["url"] = $image_thumbnail;
            $itemObj["date"] = $item->importTime;
            $itemObj["datecreated"] = $item->creationTime;
            $itemObj["datemodified"] = $item->lastUpdate;
            $itemObj['children'] = null;
            $itemObj["image_width"] = $item->width;
            $itemObj["image_height"] = $item->height;
            $itemObj['thumbnail_height'] = $thumbnail_height;
            $itemObj['thumbnail_width'] = $thumbnail_width;
        } else
            throw new RuntimeException("Unknown data type");

        $itemObj["icon"] = $itemObj["thumbnail"];

        return $itemObj;
    }


    public function print_search()
    {
        // The default implementation in class 'repository'
        global $PAGE;
        $renderer = $PAGE->get_renderer('core', 'files');
        return $renderer->repository_default_searchform();
    }

    public function search($search_text, $page = 0)
    {
        return $this->get_listing('', 1, $search_text);
    }


    /**
     * Displays a thumbnail for current user's omero file
     *
     * @param string $string
     */
    public function send_thumbnail($source)
    {
        global $CFG;
        debugging("#### send_thumbnail");
        $saveas = $this->prepare_file('');
        try {
            $access_key = get_user_preferences($this->setting . '_access_key', '');
            $access_secret = get_user_preferences($this->setting . '_access_secret', '');
            $this->omero->get_thumbnail($source, $saveas, $CFG->repositorysyncimagetimeout);
            $content = file_get_contents($saveas);
            unlink($saveas);
            // set 30 days lifetime for the image. If the image is changed in omero it will have
            // different revision number and URL will be different. It is completely safe
            // to cache thumbnail in the browser for a long time
            send_file($content, basename($source), 30 * 24 * 60 * 60, 0, true);
        } catch (Exception $e) {
        }
    }

    /**
     * Logout from omero
     * @return array
     */
    public function logout()
    {
        set_user_preference($this->setting . '_access_key', '');
        set_user_preference($this->setting . '_access_secret', '');
        $this->access_key = '';
        $this->access_secret = '';
        return $this->print_login();
    }

    /**
     * Set omero option
     * @param array $options
     * @return mixed
     */
    public function set_option($options = array())
    {
        if (!empty($options['omero_apiversion'])) {
            set_config('omero_apiversion', trim($options['omero_apiversion']), 'omero');
        }
        if (!empty($options['omero_restendpoint'])) {
            set_config('omero_restendpoint', trim($options['omero_restendpoint']), 'omero');
        }
        if (!empty($options['omero_key'])) {
            set_config('omero_key', trim($options['omero_key']), 'omero');
        }
        if (!empty($options['omero_secret'])) {
            set_config('omero_secret', trim($options['omero_secret']), 'omero');
        }
        if (!empty($options['omero_cachelimit'])) {
            $this->cachelimit = (int)trim($options['omero_cachelimit']);
            set_config('omero_cachelimit', $this->cachelimit, 'omero');
        }

        unset($options['omero_restendpoint']);
        unset($options['omero_key']);
        unset($options['omero_secret']);
        unset($options['omero_cachelimit']);
        unset($options['omero_api_version']);
        $ret = parent::set_option($options);
        return $ret;
    }

    /**
     * Get omero options
     * @param string $config
     * @return mixed
     */
    public function get_option($config = '')
    {
        if ($config === 'omero_apiversion') {
            return trim(get_config('omero', 'omero_apiversion'));
        } elseif ($config === 'omero_key') {
            return trim(get_config('omero', 'omero_key'));
        } elseif ($config === 'omero_secret') {
            return trim(get_config('omero', 'omero_secret'));
        } elseif ($config === 'omero_cachelimit') {
            return $this->max_cache_bytes();
        } else {
            $options = parent::get_option();
            $options['omero_apiversion'] = trim(get_config('omero', 'omero_apiversion'));
            $options['omero_key'] = trim(get_config('omero', 'omero_key'));
            $options['omero_secret'] = trim(get_config('omero', 'omero_secret'));
            $options['omero_cachelimit'] = $this->max_cache_bytes();
        }
        return $options;
    }

    /**
     * Fixes references in DB that contains user credentials
     *
     * @param string $reference contents of DB field files_reference.reference
     * @return string
     */
    public function fix_old_style_reference($reference)
    {
        global $CFG;
        $ref = unserialize($reference);
        if (!isset($ref->url)) {
            $ref->url = $this->omero->get_file_share_link($ref->path, $CFG->repositorygetfiletimeout);
            if (!$ref->url) {
                // some error occurred, do not fix reference for now
                return $reference;
            }
        }
        unset($ref->access_key);
        unset($ref->access_secret);
        $newreference = serialize($ref);
        if ($newreference !== $reference) {
            // we need to update references in the database
            global $DB;
            $params = array(
                'newreference' => $newreference,
                'newhash' => sha1($newreference),
                'reference' => $reference,
                'hash' => sha1($reference),
                'repoid' => $this->id
            );
            $refid = $DB->get_field_sql('SELECT id FROM {files_reference}
                WHERE reference = :reference AND referencehash = :hash
                AND repositoryid = :repoid', $params);
            if (!$refid) {
                return $newreference;
            }
            $existingrefid = $DB->get_field_sql('SELECT id FROM {files_reference}
                    WHERE reference = :newreference AND referencehash = :newhash
                    AND repositoryid = :repoid', $params);
            if ($existingrefid) {
                // the same reference already exists, we unlink all files from it,
                // link them to the current reference and remove the old one
                $DB->execute('UPDATE {files} SET referencefileid = :refid
                    WHERE referencefileid = :existingrefid',
                    array('refid' => $refid, 'existingrefid' => $existingrefid));
                $DB->delete_records('files_reference', array('id' => $existingrefid));
            }
            // update the reference
            $params['refid'] = $refid;
            $DB->execute('UPDATE {files_reference}
                SET reference = :newreference, referencehash = :newhash
                WHERE id = :refid', $params);
        }
        return $newreference;
    }

    /**
     * Converts a URL received from omero API function 'shares' into URL that
     * can be used to download/access file directly
     *
     * @param string $sharedurl
     * @return string
     */
    private function get_file_download_link($sharedurl)
    {
        return preg_replace('|^(\w*://)www(.omero.com)|', '\1dl\2', $sharedurl);
    }

    /**
     * Downloads a file from external repository and saves it in temp dir
     *
     * @throws moodle_exception when file could not be downloaded
     *
     * @param string $reference the content of files.reference field or result of
     * function {@link repository_omero::get_file_reference()}
     * @param string $saveas filename (without path) to save the downloaded file in the
     * temporary directory, if omitted or file already exists the new filename will be generated
     * @return array with elements:
     *   path: internal location of the file
     *   url: URL to the source (from parameters)
     */
    public function get_file($reference, $saveas = '')
    {
        debugging("### get_file ###");

        global $CFG;
        $ref = unserialize($reference);
        $saveas = $this->prepare_file($saveas);
        if (isset($ref->access_key) && isset($ref->access_secret) && isset($ref->path)) {
            return $this->omero->get_file($ref->path, $saveas, $CFG->repositorygetfiletimeout);
        } else if (isset($ref->url)) {
            $c = new curl;
            $url = $this->get_file_download_link($ref->url);
            $result = $c->download_one($url, null, array('filepath' => $saveas, 'timeout' => $CFG->repositorygetfiletimeout, 'followlocation' => true));
            $info = $c->get_info();
            if ($result !== true || !isset($info['http_code']) || $info['http_code'] != 200) {
                throw new moodle_exception('errorwhiledownload', 'repository', '', $result);
            }
            return array('path' => $saveas, 'url' => $url);
        }
        throw new moodle_exception('cannotdownload', 'repository');
    }

    /**
     * Add Plugin settings input to Moodle form
     *
     * @param moodleform $mform Moodle form (passed by reference)
     * @param string $classname repository class name
     */
    public static function type_config_form($mform, $classname = 'repository')
    {
        global $CFG;
        parent::type_config_form($mform);

        $api_version = get_config('omero', 'omero_apiversion');
        $endpoint = get_config('omero', 'omero_restendpoint');
        $webclient = get_config('omero', 'omero_webclient');
        $key = get_config('omero', 'omero_key');
        $secret = get_config('omero', 'omero_secret');

        if (empty($api_version)) {
            $api_version = array_keys(self::$API_VERSIONS)[0];
        }
        if (empty($endpoint)) {
            $endpoint = 'http://omero.crs4.it:8080';
        }
        if (empty($webclient)) {
            $webclient = $endpoint;
        }
        if (empty($key)) {
            $key = '';
        }
        if (empty($secret)) {
            $secret = '';
        }

        $strrequired = get_string('required');

        $mform->addElement('text', 'omero_restendpoint', get_string('omero_server', 'repository_omero'), array('value' => $endpoint, 'size' => '80'));
        $mform->setType('omero_restendpoint', PARAM_RAW_TRIMMED);

        $mform->addElement('text', 'omero_webclient', get_string('omero_webclient', 'repository_omero'), array('value' => $webclient, 'size' => '80'));
        $mform->setType('omero_webclient', PARAM_RAW_TRIMMED);

        $mform->addElement('select', 'omero_apiversion',
            get_string('apiversion', 'repository_omero'), self::$API_VERSIONS);
        $mform->setDefault('omero_apiversion', $api_version);

        $mform->addElement('text', 'omero_key', get_string('apikey', 'repository_omero'), array('value' => $key, 'size' => '40'));
        $mform->setType('omero_key', PARAM_RAW_TRIMMED);
        $mform->addElement('text', 'omero_secret', get_string('apisecret', 'repository_omero'), array('value' => $secret, 'size' => '40'));

        $mform->addRule('omero_key', $strrequired, 'required', null, 'client');
        $mform->addRule('omero_secret', $strrequired, 'required', null, 'client');
        $mform->setType('omero_secret', PARAM_RAW_TRIMMED);
        $str_getkey = get_string('instruction', 'repository_omero');
        $mform->addElement('static', null, '', $str_getkey);

        $mform->addElement('text', 'omero_cachelimit', get_string('cachelimit', 'repository_omero'), array('size' => '40'));
        $mform->addRule('omero_cachelimit', null, 'numeric', null, 'client');
        $mform->setType('omero_cachelimit', PARAM_INT);
        $mform->addElement('static', 'omero_cachelimit_info', '', get_string('cachelimit_info', 'repository_omero'));
    }

    /**
     * Option names of omero plugin
     *
     * @return array
     */
    public static function get_type_option_names()
    {
        return array(
            'pluginname',
            'omero_apiversion',
            'omero_restendpoint',
            'omero_webclient',
            'omero_key', 'omero_secret',
            'omero_cachelimit'
        );
    }

    /**
     * omero plugin supports all kinds of files
     *
     * @return array
     */
    public function supported_filetypes()
    {
        return array('image/png');
    }

    /**
     * User cannot use the external link to omero
     *
     * @return int
     */
    public function supported_returntypes()
    {
        return /*FILE_INTERNAL |*/
            //FILE_REFERENCE |
            FILE_EXTERNAL;
    }

    /**
     * Return file URL for external link
     *
     * @param string $reference the result of get_file_reference()
     * @return string
     */
    public function get_link($reference)
    {
        global $CFG;
        debugging("get_link called: : $reference !!!");
        $ref = unserialize($reference);
        if (!isset($ref->url)) {
            $ref->url = $this->omero->get_file_share_link($ref->path, $CFG->repositorygetfiletimeout);
        }
        return $ref->path;
    }

    /**
     * Prepare file reference information
     *
     * @param string $source
     * @return string file referece
     */
    public function get_file_reference($source)
    {
        global $USER, $CFG;

        debugging("---> Calling 'get_file_reference: $source' <---");

        $reference = new stdClass;
        $reference->path = "/omero-image-repository/$source";
        $reference->userid = $USER->id;
        $reference->username = fullname($USER);

        // by API we don't know if we need this reference to just download a file from omero
        // into moodle filepool or create a reference. Since we need to create a shared link
        // only in case of reference we analyze the script parameter
        $usefilereference = optional_param('usefilereference', false, PARAM_BOOL);
        if ($usefilereference) {
            debugging("Computing reference: $usefilereference");
            $url = $this->omero->get_file_share_link($source, $CFG->repositorygetfiletimeout);
            if ($url) {
                unset($reference->access_key);
                unset($reference->access_secret);
                $reference->url = $this->omero->URLS->get_image_url($source);
                debugging("Computed reference: " . $reference->url);
            }
        }
        return serialize($reference);
    }

    public function sync_reference(stored_file $file)
    {
        debugging("---> Calling 'sync_reference' <---");
        global $CFG;
        if ($file->get_referencelastsync() + DAYSECS > time()) {
            // Synchronise not more often than once a day.
            return false;
        }
        $ref = unserialize($file->get_reference());
        if (!isset($ref->url)) {
            // this is an old-style reference in DB. We need to fix it
            $ref = unserialize($this->fix_old_style_reference($file->get_reference()));
        }
        if (!isset($ref->url)) {
            return false;
        }
        $c = new curl;
        $url = $this->get_file_download_link($ref->url);
        if (file_extension_in_typegroup($ref->path, 'web_image')) {
            $saveas = $this->prepare_file('');
            try {
                $result = $c->download_one($url, array(),
                    array('filepath' => $saveas,
                        'timeout' => $CFG->repositorysyncimagetimeout,
                        'followlocation' => true));
                $info = $c->get_info();
                if ($result === true && isset($info['http_code']) && $info['http_code'] == 200) {
                    $fs = get_file_storage();
                    list($contenthash, $filesize, $newfile) = $fs->add_file_to_pool($saveas);
                    $file->set_synchronized($contenthash, $filesize);
                    return true;
                }
            } catch (Exception $e) {
            }
        }
        $c->get($url, null, array(
            'timeout' => $CFG->repositorysyncimagetimeout, 'followlocation' => true, 'nobody' => true
        ));
        $info = $c->get_info();
        if (isset($info['http_code']) && $info['http_code'] == 200 &&
            array_key_exists('download_content_length', $info) &&
            $info['download_content_length'] >= 0
        ) {
            $filesize = (int)$info['download_content_length'];
            $file->set_synchronized(null, $filesize);
            return true;
        }
        $file->set_missingsource();
        return true;
    }

    /**
     * Cache file from external repository by reference
     *
     * omero repository regularly caches all external files that are smaller than
     * {@link repository_omero::max_cache_bytes()}
     *
     * @param string $reference this reference is generated by
     *                          repository::get_file_reference()
     * @param stored_file $storedfile created file reference
     */
    public function cache_file_by_reference($reference, $storedfile)
    {
        debugging("---> Calling 'cache_file_by_reference' <---");
        try {
            $this->import_external_file_contents($storedfile, $this->max_cache_bytes());
        } catch (Exception $e) {
        }
    }

    /**
     * Return human readable reference information
     * {@link stored_file::get_reference()}
     *
     * @param string $reference
     * @param int $filestatus status of the file, 0 - ok, 666 - source missing
     * @return string
     */
    public function get_reference_details($reference, $filestatus = 0)
    {
        debugging("---> Calling 'get_reference_details' <---");
        global $USER;
        $ref = unserialize($reference);
        $detailsprefix = $this->get_name();
        if (isset($ref->userid) && $ref->userid != $USER->id && isset($ref->username)) {
            $detailsprefix .= ' (' . $ref->username . ')';
        }
        $details = $detailsprefix;
        if (isset($ref->path)) {
            $details .= ': ' . $ref->path;
        }
        if (isset($ref->path) && !$filestatus) {
            // Indicate this is from omero with path
            return $details;
        } else {
            if (isset($ref->url)) {
                $details = $detailsprefix . ': ' . $ref->url;
            }
            return get_string('lostsource', 'repository', $details);
        }
    }

    /**
     * Return the source information
     *
     * @param string $source
     * @return string
     */
    public function get_file_source_info($source)
    {
        global $USER;
        return 'omero (' . fullname($USER) . '): ' . $source;
    }

    /**
     * Returns the maximum size of the omero files to cache in moodle
     *
     * Note that {@link repository_omero::sync_reference()} will try to cache images even
     * when they are bigger in order to generate thumbnails. However there is
     * a small timeout for downloading images for synchronisation and it will
     * probably fail if the image is too big.
     *
     * @return int
     */
    public function max_cache_bytes()
    {
        if ($this->cachelimit === null) {
            $this->cachelimit = (int)get_config('omero', 'omero_cachelimit');
        }
        return $this->cachelimit;
    }

    /**
     * Repository method to serve the referenced file
     *
     * This method is ivoked from {@link send_stored_file()}.
     * omero repository first caches the file by reading it into temporary folder and then
     * serves from there.
     *
     * @param stored_file $storedfile the file that contains the reference
     * @param int $lifetime Number of seconds before the file should expire from caches (null means $CFG->filelifetime)
     * @param int $filter 0 (default)=no filtering, 1=all files, 2=html files only
     * @param bool $forcedownload If true (default false), forces download of file rather than view in browser/plugin
     * @param array $options additional options affecting the file serving
     */
    public function send_file($storedfile, $lifetime = null, $filter = 0, $forcedownload = false, array $options = null)
    {
        debugging("---> Calling 'send_file' <---");

        $ref = unserialize($storedfile->get_reference());
        if ($storedfile->get_filesize() > $this->max_cache_bytes()) {
            header('Location: ' . $this->get_file_download_link($ref->url));
            die;
        }
        try {
            $this->import_external_file_contents($storedfile, $this->max_cache_bytes());
            if (!is_array($options)) {
                $options = array();
            }
            $options['sendcachedexternalfile'] = true;
            send_stored_file($storedfile, $lifetime, $filter, $forcedownload, $options);
        } catch (moodle_exception $e) {
            // redirect to omero, it will show the error.
            // We redirect to omero shared link, not to download link here!
            header('Location: ' . $ref->url);
            die;
        }
    }

    /**
     * Caches all references to omero files in moodle filepool
     *
     * Invoked by {@link repository_omero_cron()}. Only files smaller than
     * {@link repository_omero::max_cache_bytes()} and only files which
     * synchronisation timeout have not expired are cached.
     */
    public function cron()
    {
        $fs = get_file_storage();
        $files = $fs->get_external_files($this->id);
        foreach ($files as $file) {
            try {
                // This call will cache all files that are smaller than max_cache_bytes()
                // and synchronise file size of all others
                $this->import_external_file_contents($file, $this->max_cache_bytes());
            } catch (moodle_exception $e) {
            }
        }
    }


    /**
     * Return the relative icon path for a folder image
     *
     * Usage:
     * <code>
     * $icon = $OUTPUT->pix_url(file_folder_icon())->out();
     * echo html_writer::empty_tag('img', array('src' => $icon));
     * </code>
     * or
     * <code>
     * echo $OUTPUT->pix_icon(file_folder_icon(32));
     * </code>
     *
     * @param int $iconsize The size of the icon. Defaults to 16 can also be 24, 32, 48, 64, 72, 80, 96, 128, 256
     * @return string
     */
    function file_icon($iconname, $iconsize = null)
    {
        global $CFG;

        static $iconpostfixes = array(256 => '-256', 128 => '-128', 96 => '-96', 80 => '-80', 72 => '-72', 64 => '-64', 48 => '-48', 32 => '-32', 24 => '-24', 16 => '');
        static $cached = array();
        $iconsize = max(array(16, (int)$iconsize));
        if (!array_key_exists($iconsize, $cached)) {
            foreach ($iconpostfixes as $size => $postfix) {
                $fullname = $CFG->wwwroot . "/repository/omero/pix/$iconname/$iconsize.png";
                return $fullname;
                if ($iconsize >= $size && (file_exists($fullname)))
                    return $fullname;
            }
        }
        return $cached[$iconsize];
    }
}

