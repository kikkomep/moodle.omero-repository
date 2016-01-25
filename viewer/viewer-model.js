/**
 * The instance of the Image Model Manager
 *
 * @type {{image__model_manager}}
 */
image_model_manager = {};

// internal shortcut for the manager instance
var mgt = image_model_manager;

/**
 * Initialize the model manager of the actual omero viewer
 *
 * @param image_server the actual image server URL (e.g., http://omero.crs4.it:8080)
 * @param image_id the ID of the image to manage
 */
function ImageModelManager(image_server, image_id) {

    // register the address of the current OMERO server
    this._image_server = image_server;

    // register the ID of the image to manage
    this._image_id = image_id;

    // event listeners
    this._listeners = [];

    // log init status
    console.info("image_model_manager initialized!!!")
};


/**
 * Registers the <pre>listener</pre> of the model events
 * triggered by this 'model'
 *
 * @param listener
 */
ImageModelManager.prototype.addEventListener = function (listener) {
    if (!listener) return;
    this._listeners.push(listener);
};


/**
 * Deregisters the <pre>listener</pre> from this model
 *
 * @param listener
 */
ImageModelManager.prototype.removeEventListener = function (listener) {
    if (!listener) return;
    var index = this._listeners.indexOf(listener);
    if (index > -1)
        this._listeners.splice(index, 1);
};


/**
 * Notifies an event to the registered listeners
 *
 * @param event
 * @private
 */
ImageModelManager.prototype._notifyListeners = function (event) {
    if (event) {
        console.log("Event", event);
        for (var i in this._listeners) {
            var callbackName = "on" + event.type.charAt(0).toUpperCase() + event.type.slice(1);
            console.log("Listener", i, this._listeners[i], callbackName);
            var callback = this._listeners[i][callbackName];
            if (callback) {
                console.log("Calling ", callback);
                callback.call(this._listeners[i], event);
            }
        }
    }
};


/**
 * Load info of ROIs related to the current image
 *
 * @param image_id
 * @param success_callback
 * @param error_callback
 * @private
 */
ImageModelManager.prototype.loadRoisInfo = function (success_callback, error_callback) {

    var me = this;

    $.ajax({
        url: this._image_server + "/webgateway/get_rois_json/" + this._image_id,

        // The name of the callback parameter, as specified by the YQL service
        jsonp: "callback",

        // Tell jQuery we're expecting JSONP
        dataType: "jsonp",

        // Request parameters
        data: {
            q: "", //FIXME: not required
            format: "json"
        },

        // Set callback methods
        success: function (data) {

            // post process data:
            // adapt the model removing OMERO complexity
            var result = [];
            $.each(data, function (index) {
                var obj = $(this)[0];
                result[index] = obj.shapes[0];
            });

            if (success_callback) {
                success_callback(data);
            }

            // Notify that ROI info are loaded
            me._notifyListeners(new CustomEvent(
                "imageModelRoiLoaded",
                {
                    detail: data,
                    bubbles: true
                })
            );
        },
        error: error_callback
    });
};