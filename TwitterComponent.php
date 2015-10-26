<?php
class TwitterComponent extends Component {
  const DEBUG = false;

  const API_URL = 'https://api.twitter.com/1.1';
  const SECURE_API_URL = 'https://api.twitter.com';

  const API_PORT = 443;
  const SECURE_API_PORT = 443;

  const VERSION = '2.3.1';

  protected $curl;

  protected $consumerKey;

  protected $consumerSecret;

  protected $oAuthToken = '';

  protected $oAuthTokenSecret = '';

  protected $timeOut = 10;

  protected $userAgent;

  // class methods
  /**
   * Default constructor
   *
   * @param string $consumerKey    The consumer key to use.
   * @param string $consumerSecret The consumer secret to use.
   */
  public function __construct($consumerKey, $consumerSecret) {
    $this->setConsumerKey(/** YOUR CONSUMER KEY **/);
    $this->setConsumerSecret(/** YOUR CONSUMER SECRET **/);
    $this->setOAuthToken(/** YOUR OAUTH TOKEN **/);
    $this->setOAuthTokenSecret(/** YOUR OAUTH TOKEN SECRET **/);
  }

  /**
   * Default destructor
   */
  public function __destruct() {
    if($this->curl != null) curl_close($this->curl);
  }

  /**
   * Format the parameters as a querystring
   *
   * @param  array  $parameters The parameters.
   * @return string
   */
  protected function buildQuery(array $parameters) {
    // no parameters?
    if(empty($parameters)) return '';

    // encode the keys
    $keys = self::urlencode_rfc3986(array_keys($parameters));

    // encode the values
    $values = self::urlencode_rfc3986(array_values($parameters));

    // reset the parameters
    $parameters = array_combine($keys, $values);

    // sort parameters by key
    uksort($parameters, 'strcmp');

    // loop parameters
    foreach ($parameters as $key => $value) {
      // sort by value
      if(is_array($value)) $parameters[$key] = natsort($value);
    }

    // process parameters
    foreach ($parameters as $key => $value) {
      $chunks[] = $key . '=' . str_replace('%25', '%', $value);
    }

    // return
    return implode('&', $chunks);
  }

  /**
   * All OAuth 1.0 requests use the same basic algorithm for creating a
   * signature base string and a signature. The signature base string is
   * composed of the HTTP method being used, followed by an ampersand ("&")
   * and then the URL-encoded base URL being accessed, complete with path
   * (but not query parameters), followed by an ampersand ("&"). Then, you
   * take all query parameters and POST body parameters (when the POST body is
   * of the URL-encoded type, otherwise the POST body is ignored), including
   * the OAuth parameters necessary for negotiation with the request at hand,
   * and sort them in lexicographical order by first parameter name and then
   * parameter value (for duplicate parameters), all the while ensuring that
   * both the key and the value for each parameter are URL encoded in
   * isolation. Instead of using the equals ("=") sign to mark the key/value
   * relationship, you use the URL-encoded form of "%3D". Each parameter is
   * then joined by the URL-escaped ampersand sign, "%26".
   *
   * @param  string $url        The URL.
   * @param  string $method     The method to use.
   * @param  array  $parameters The parameters.
   * @return string
   */
  protected function calculateBaseString($url, $method, array $parameters) {
    // redefine
    $url = (string) $url;
    $parameters = (array) $parameters;

    // init var
    $pairs = array();
    $chunks = array();

    // sort parameters by key
    uksort($parameters, 'strcmp');

    // loop parameters
    foreach ($parameters as $key => $value) {
      // sort by value
      if(is_array($value)) $parameters[$key] = natsort($value);
    }

    // process queries
    foreach ($parameters as $key => $value) {
      // only add if not already in the url
      if (substr_count($url, $key . '=' . $value) == 0) {
        $chunks[] = self::urlencode_rfc3986($key) . '%3D' .
                    self::urlencode_rfc3986($value);
      }
    }

    // buils base
    $base = $method . '&';
    $base .= urlencode($url);
    $base .= (substr_count($url, '?')) ? '%26' : '&';
    $base .= implode('%26', $chunks);
    $base = str_replace('%3F', '&', $base);

    // return
    return $base;
  }

  /**
   * Build the Authorization header
   * @later: fix me
   *
   * @param  array  $parameters The parameters.
   * @param  string $url        The URL.
   * @return string
   */
  protected function calculateHeader(array $parameters, $url) {
    // redefine
    $url = (string) $url;

    // divide into parts
    $parts = parse_url($url);

    // init var
    $chunks = array();

    // process queries
    foreach ($parameters as $key => $value) {
      $chunks[] = str_replace(
        '%25', '%',
        self::urlencode_rfc3986($key) . '="' . self::urlencode_rfc3986($value) . '"'
      );
    }

    // build return
    $return = 'Authorization: OAuth realm="' . $parts['scheme'] . '://' .
              $parts['host'] . $parts['path'] . '", ';
    $return .= implode(',', $chunks);

    // prepend name and OAuth part
    return $return;
  }

  /**
   * Make an call to the oAuth
   * @todo    refactor me
   *
   * @param  string          $method     The method.
   * @param  array[optional] $parameters The parameters.
   * @return array
   */
  protected function doOAuthCall($method, array $parameters = null) {
    // redefine
    $method = (string) $method;

    // append default parameters
    $parameters['oauth_consumer_key'] = $this->getConsumerKey();
    $parameters['oauth_nonce'] = md5(microtime() . rand());
    $parameters['oauth_timestamp'] = time();
    $parameters['oauth_signature_method'] = 'HMAC-SHA1';
    $parameters['oauth_version'] = '1.0';

    // calculate the base string
    $base = $this->calculateBaseString(
      self::SECURE_API_URL . '/oauth/' . $method, 'POST', $parameters
    );

    // add sign into the parameters
    $parameters['oauth_signature'] = $this->hmacsha1(
      $this->getConsumerSecret() . '&' . $this->getOAuthTokenSecret(),
      $base
    );

    // calculate header
    $header = $this->calculateHeader(
      $parameters,
      self::SECURE_API_URL . '/oauth/' . $method
    );

    // set options
    $options[CURLOPT_URL] = self::SECURE_API_URL . '/oauth/' . $method;
    $options[CURLOPT_PORT] = self::SECURE_API_PORT;
    $options[CURLOPT_USERAGENT] = $this->getUserAgent();
    if (ini_get('open_basedir') == '' && ini_get('safe_mode' == 'Off')) {
      $options[CURLOPT_FOLLOWLOCATION] = true;
    }
    $options[CURLOPT_RETURNTRANSFER] = true;
    $options[CURLOPT_TIMEOUT] = (int) $this->getTimeOut();
    $options[CURLOPT_SSL_VERIFYPEER] = false;
    $options[CURLOPT_SSL_VERIFYHOST] = false;
    $options[CURLOPT_HTTPHEADER] = array('Expect:');
    $options[CURLOPT_POST] = true;
    $options[CURLOPT_POSTFIELDS] = $this->buildQuery($parameters);

    // init
    $this->curl = curl_init();

    // set options
    curl_setopt_array($this->curl, $options);

    // execute
    $response = curl_exec($this->curl);
    $headers = curl_getinfo($this->curl);

    // fetch errors
    $errorNumber = curl_errno($this->curl);
    $errorMessage = curl_error($this->curl);

    // error?
    if ($errorNumber != '') {
      throw new Exception($errorMessage, $errorNumber);
    }

    // init var
    $return = array();

    // parse the string
    parse_str($response, $return);

    // return
    return $return;
  }

  /**
   * Make the call
   *
   * @param  string           $url           The url to call.
   * @param  array[optional]  $parameters    Optional parameters.
   * @param  bool[optional]   $authenticate  Should we authenticate.
   * @param  bool[optional]   $method        The method to use. Possible values are GET, POST.
   * @param  string[optional] $filePath      The path to the file to upload.
   * @param  bool[optional]   $expectJSON    Do we expect JSON.
   * @param  bool[optional]   $returnHeaders Should the headers be returned?
   * @return string
   */
  protected function doCall(
    $url, array $parameters = null, $authenticate = false, $method = 'GET',
    $filePath = null, $expectJSON = true, $returnHeaders = false
  ) {
    // allowed methods
    $allowedMethods = array('GET', 'POST');

    // redefine
    $url = (string) $url;
    $parameters = (array) $parameters;
    $authenticate = (bool) $authenticate;
    $method = (string) $method;
    $expectJSON = (bool) $expectJSON;

    // validate method
    if (!in_array($method, $allowedMethods)) {
      throw new Exception(
        'Unknown method (' . $method . '). Allowed methods are: ' .
        implode(', ', $allowedMethods)
      );
    }

    // append default parameters
    $oauth['oauth_consumer_key'] = $this->getConsumerKey();
    $oauth['oauth_nonce'] = md5(microtime() . rand());
    $oauth['oauth_timestamp'] = time();
    $oauth['oauth_token'] = $this->getOAuthToken();
    $oauth['oauth_signature_method'] = 'HMAC-SHA1';
    $oauth['oauth_version'] = '1.0';

    // set data
    $data = $oauth;
    if(!empty($parameters)) $data = array_merge($data, $parameters);

    // calculate the base string
    $base = $this->calculateBaseString(
      self::API_URL . '/' . $url, $method, $data
    );

    // based on the method, we should handle the parameters in a different way
    if ($method == 'POST') {
      // file provided?
      if ($filePath != null) {
        // build a boundary
        $boundary = md5(time());

        // process file
        $fileInfo = pathinfo($filePath);

        // set mimeType
        $mimeType = 'application/octet-stream';
        if ($fileInfo['extension'] == 'jpg' || $fileInfo['extension'] == 'jpeg') {
            $mimeType = 'image/jpeg';
        } elseif($fileInfo['extension'] == 'gif') $mimeType = 'image/gif';
        elseif($fileInfo['extension'] == 'png') $mimeType = 'image/png';

        // init var
        $content = '--' . $boundary . "\r\n";

        // set file
        $content .= 'Content-Disposition: form-data; name=image; filename="' .
                    $fileInfo['basename'] . '"' . "\r\n";
        $content .= 'Content-Type: ' . $mimeType . "\r\n";
        $content .= "\r\n";
        $content .= file_get_contents($filePath);
        $content .= "\r\n";
        $content .= "--" . $boundary . '--';

        // build headers
        $headers[] = 'Content-Type: multipart/form-data; boundary=' . $boundary;
        $headers[] = 'Content-Length: ' . strlen($content);

        // set content
        $options[CURLOPT_POSTFIELDS] = $content;
      }

      // no file
      else $options[CURLOPT_POSTFIELDS] = $this->buildQuery($parameters);

      // enable post
      $options[CURLOPT_POST] = true;
    } else {
        // add the parameters into the querystring
        if(!empty($parameters)) $url .= '?' . $this->buildQuery($parameters);
        $options[CURLOPT_POST] = false;
    }

    // add sign into the parameters
    $oauth['oauth_signature'] = $this->hmacsha1(
        $this->getConsumerSecret() . '&' . $this->getOAuthTokenSecret(),
        $base
    );

    $headers[] = $this->calculateHeader($oauth, self::API_URL . '/' . $url);
    $headers[] = 'Expect:';

    // set options
    $options[CURLOPT_URL] = self::API_URL . '/' . $url;
    $options[CURLOPT_PORT] = self::API_PORT;
    $options[CURLOPT_USERAGENT] = $this->getUserAgent();
    if (ini_get('open_basedir') == '' && ini_get('safe_mode' == 'Off')) {
        $options[CURLOPT_FOLLOWLOCATION] = true;
    }
    $options[CURLOPT_RETURNTRANSFER] = true;
    $options[CURLOPT_TIMEOUT] = (int) $this->getTimeOut();
    $options[CURLOPT_SSL_VERIFYPEER] = false;
    $options[CURLOPT_SSL_VERIFYHOST] = false;
    $options[CURLOPT_HTTP_VERSION] = CURL_HTTP_VERSION_1_1;
    $options[CURLOPT_HTTPHEADER] = $headers;

    // init
    if($this->curl == null) $this->curl = curl_init();

    // set options
    curl_setopt_array($this->curl, $options);

    // execute
    $response = curl_exec($this->curl);
    $headers = curl_getinfo($this->curl);

    // fetch errors
    $errorNumber = curl_errno($this->curl);
    $errorMessage = curl_error($this->curl);

    // return the headers
    if($returnHeaders) return $headers;

    // we don't expext JSON, return the response
    if(!$expectJSON) return $response;

    // replace ids with their string values, added because of some
    // PHP-version can't handle these large values
    $response = preg_replace('/id":(\d+)/', 'id":"\1"', $response);

    // we expect JSON, so decode it
    $json = @json_decode($response, true);

    // validate JSON
    if ($json === null) {
      // should we provide debug information
      if (self::DEBUG) {
        // make it output proper
        echo '<pre>';

        // dump the header-information
        var_dump($headers);

        // dump the error
        var_dump($errorMessage);

        // dump the raw response
        var_dump($response);

        // end proper format
        echo '</pre>';
      }

      // throw exception
      throw new Exception('Invalid response.');
    }

    // any errors
    if (isset($json['errors'])) {
      // should we provide debug information
      if (self::DEBUG) {
        // make it output proper
        echo '<pre>';

        // dump the header-information
        var_dump($headers);

        // dump the error
        var_dump($errorMessage);

        // dump the raw response
        var_dump($response);

        // end proper format
        echo '</pre>';
      }

      // throw exception
      if (isset($json['errors'][0]['message'])) {
        throw new Exception($json['errors'][0]['message']);
      } elseif (isset($json['errors']) && is_string($json['errors'])) {
        throw new Exception($json['errors']);
      } else throw new Exception('Invalid response.');
    }

    // any error
    if (isset($json['error'])) {
      // should we provide debug information
      if (self::DEBUG) {
        // make it output proper
        echo '<pre>';

        // dump the header-information
        var_dump($headers);

        // dump the raw response
        var_dump($response);

        // end proper format
        echo '</pre>';
      }

      // throw exception
      throw new Exception($json['error']);
    }

    // return
    return $json;
  }

  /**
   * Get the consumer key
   *
   * @return string
   */
  protected function getConsumerKey() {
    return $this->consumerKey;
  }

  /**
   * Get the consumer secret
   *
   * @return string
   */
  protected function getConsumerSecret() {
    return $this->consumerSecret;
  }

  /**
   * Get the oAuth-token
   *
   * @return string
   */
  protected function getOAuthToken() {
    return $this->oAuthToken;
  }

  /**
   * Get the oAuth-token-secret
   *
   * @return string
   */
  protected function getOAuthTokenSecret() {
    return $this->oAuthTokenSecret;
  }

  /**
   * Get the timeout
   *
   * @return int
   */
  public function getTimeOut() {
    return (int) $this->timeOut;
  }

  /**
   * Get the useragent that will be used. Our version will be prepended to yours.
   * It will look like: "PHP Twitter/<version> <your-user-agent>"
   *
   * @return string
   */
  public function getUserAgent( ) {
    return (string) 'PHP Twitter/' . self::VERSION . ' ' . $this->userAgent;
  }

  /**
   * Set the consumer key
   *
   * @param string $key The consumer key to use.
   */
  protected function setConsumerKey($key ) {
    $this->consumerKey = $key;
  }

  /**
   * Set the consumer secret
   *
   * @param string $secret The consumer secret to use.
   */
  protected function setConsumerSecret($secret ) {
    $this->consumerSecret = (string) $secret;
  }

  /**
   * Set the oAuth-token
   *
   * @param string $token The token to use.
   */
  public function setOAuthToken($token ) {
    $this->oAuthToken = (string) $token;
  }

  /**
   * Set the oAuth-secret
   *
   * @param string $secret The secret to use.
   */
  public function setOAuthTokenSecret($secret ) {
    $this->oAuthTokenSecret = (string) $secret;
  }

  /**
   * Set the timeout
   *
   * @param int $seconds The timeout in seconds.
   */
  public function setTimeOut($seconds ) {
    $this->timeOut = (int) $seconds;
  }

  /**
   * Get the useragent that will be used. Our version will be prepended to yours.
   * It will look like: "PHP Twitter/<version> <your-user-agent>"
   *
   * @param string $userAgent Your user-agent, it should look like <app-name>/<app-version>.
   */
  public function setUserAgent($userAgent ) {
    $this->userAgent = (string) $userAgent;
  }

  /**
   * Build the signature for the data
   *
   * @param  string $key  The key to use for signing.
   * @param  string $data The data that has to be signed.
   * @return string
   */
  protected function hmacsha1($key, $data ) {
    return base64_encode(hash_hmac('SHA1', $data, $key, true));
  }

  /**
   * URL-encode method for internal use
   *
   * @param  mixed  $value The value to encode.
   * @return string
   */
  protected static function urlencode_rfc3986($value ) {
    if (is_array($value)) {
      return array_map(array(__CLASS__, 'urlencode_rfc3986'), $value);
    } else {
      $search = array('+', ' ', '%7E', '%');
      $replace = array('%20', '%20', '~', '%25');

      return str_replace($search, $replace, urlencode($value));
    }
  }

// Timeline resources
  /**
   * Returns the 20 most recent mentions (tweets containing a users's @screen_name) for the authenticating user.
   * The timeline returned is the equivalent of the one seen when you view your mentions on twitter.com.
   * This method can only return up to 800 tweets.
   *
   * @param  int[optional]    $count              Specifies the number of tweets to try and retrieve, up to a maximum of 200. The value of count is best thought of as a limit to the number of tweets to return because suspended or deleted content is removed after the count has been applied. We include retweets in the count, even if include_rts is not supplied.
   * @param  string[optional] $sinceId            Returns results with an ID greater than (that is, more recent than) the specified ID. There are limits to the number of Tweets which can be accessed through the API. If the limit of Tweets has occured since the since_id, the since_id will be forced to the oldest ID available.
   * @param  string[optional] $maxId              Returns results with an ID less than (that is, older than) or equal to the specified ID.
   * @param  bool[optional]   $trimUser           When set to true, each tweet returned in a timeline will include a user object including only the status authors numerical ID. Omit this parameter to receive the complete user object.
   * @param  bool[optional]   $contributorDetails This parameter enhances the contributors element of the status response to include the screen_name of the contributor. By default only the user_id of the contributor is included.
   * @param  bool[optional]   $includeEntities    The entities node will be disincluded when set to false.
   * @return array
   */
  public function statusesMentionsTimeline(
    $count = null, $sinceId = null, $maxId = null,
    $trimUser = null, $contributorDetails = null, $includeEntities = null
  ) {
    // build parameters
    $parameters = null;
    $parameters['include_rts'] = 'true';
    if ($count != null) {
      $parameters['count'] = (int) $count;
    }
    if ($sinceId != null) {
      $parameters['since_id'] = (string) $sinceId;
    }
    if ($maxId != null) {
      $parameters['max_id'] = (string) $maxId;
    }
    if ($trimUser !== null) {
      $parameters['trim_user'] = ($trimUser) ? 'true' : 'false';
    }
    if ($contributorDetails !== null) {
      $parameters['contributor_details'] = ($contributorDetails) ? 'true' : 'false';
    }
    if ($includeEntities !== null) {
      $parameters['include_entities'] = ($includeEntities) ? 'true' : 'false';
    }

    // make the call
    return (array) $this->doCall(
      'statuses/mentions_timeline.json',
      $parameters, true
    );
  }

  /**
   * Returns a collection of the most recent Tweets posted by the user indicated by the screen_name or user_id parameters.
   * User timelines belonging to protected users may only be requested when the authenticated user either "owns" the timeline or is an approved follower of the owner.
   * The timeline returned is the equivalent of the one seen when you view a user's profile on twitter.com.
   * This method can only return up to 3,200 of a user's most recent Tweets. Native retweets of other statuses by the user is included in this total, regardless of whether include_rts is set to false when requesting this resource.
   *
   * @param  string[optional] $userId             The ID of the user for whom to return results for. Helpful for disambiguating when a valid user ID is also a valid screen name.
   * @param  string[optional] $screenName         The screen name of the user for whom to return results for. Helpful for disambiguating when a valid screen name is also a user ID.
   * @param  string[optional] $sinceId            Returns results with an ID greater than (that is, more recent than) the specified ID. There are limits to the number of Tweets which can be accessed through the API. If the limit of Tweets has occured since the since_id, the since_id will be forced to the oldest ID available.
   * @param  int[optional]    $count              Specifies the number of tweets to try and retrieve, up to a maximum of 200 per distinct request. The value of count is best thought of as a limit to the number of tweets to return because suspended or deleted content is removed after the count has been applied. We include retweets in the count, even if include_rts is not supplied.
   * @param  string[optional] $maxId              Returns results with an ID less than (that is, older than) or equal to the specified ID.
   * @param  bool[optional]   $trimUser           When set to true, each tweet returned in a timeline will include a user object including only the status authors numerical ID. Omit this parameter to receive the complete user object.
   * @param  bool[optional]   $excludeReplies     This parameter will prevent replies from appearing in the returned timeline. Using exclude_replies with the count parameter will mean you will receive up-to count tweets — this is because the count parameter retrieves that many tweets before filtering out retweets and replies.
   * @param  bool[optional]   $contributorDetails This parameter enhances the contributors element of the status response to include the screen_name of the contributor. By default only the user_id of the contributor is included.
   * @param  bool[optional]   $includeRts         When set to false, the timeline will strip any native retweets (though they will still count toward both the maximal length of the timeline and the slice selected by the count parameter). Note: If you're using the trim_user parameter in conjunction with include_rts, the retweets will still contain a full user object.
   * @return array
   */
  public function statusesUserTimeline(
    $userId = null, $screenName = null, $sinceId = null, $count = null,
    $maxId = null, $trimUser = null, $excludeReplies = null,
    $contributorDetails = null, $includeRts = null
   ) {
    // validate
    if ($userId == '' && $screenName == '') {
        throw new Exception('Specify an userId or a screenName.');
    }

    // build parameters
    $parameters = null;
    if ($userId != null) {
        $parameters['user_id'] = (string) $userId;
    }
    if ($screenName != null) {
        $parameters['screen_name'] = (string) $screenName;
    }
    if ($sinceId != null) {
        $parameters['since_id'] = (string) $sinceId;
    }
    if ($count != null) {
        $parameters['count'] = (int) $count;
    }
    if ($maxId != null) {
        $parameters['max_id'] = (string) $maxId;
    }
    if ($trimUser !== null) {
        $parameters['trim_user'] = ($trimUser) ? 'true' : 'false';
    }
    if ($excludeReplies !== null) {
        $parameters['exclude_replies'] = ($excludeReplies) ? 'true' : 'false';
    }
    if ($contributorDetails !== null) {
        $parameters['contributor_details'] = ($contributorDetails) ? 'true' : 'false';
    }
    if ($includeRts !== null) {
        $parameters['include_rts'] = ($includeRts) ? 'true' : 'false';
    }

    // make the call
    return (array) $this->doCall(
      'statuses/user_timeline.json',
      $parameters
    );
  }

  /**
   * @param  string[optional] $id         The Tweet/status ID to return embed code for.
   * @param  string[optional] $url        The URL of the Tweet/status to be embedded.
   * @param  int[optional]    $maxwidth   The maximum width in pixels that the embed should be rendered at. This value is constrained to be between 250 and 550 pixels. Note that Twitter does not support the oEmbed maxheight parameter. Tweets are fundamentally text, and are therefore of unpredictable height that cannot be scaled like an image or video. Relatedly, the oEmbed response will not provide a value for height. Implementations that need consistent heights for Tweets should refer to the hide_thread and hide_media parameters below.
   * @param  bool[optional]   $hideMedia  Specifies whether the embedded Tweet should automatically expand images which were uploaded via POST statuses/update_with_media. When set to true images will not be expanded. Defaults to false.
   * @param  bool[optional]   $hideThread Specifies whether the embedded Tweet should automatically show the original message in the case that the embedded Tweet is a reply. When set to true the original Tweet will not be shown. Defaults to false.
   * @param  bool[optional]   $omitScript Specifies whether the embedded Tweet HTML should include a <script> element pointing to widgets.js. In cases where a page already includes widgets.js, setting this value to true will prevent a redundant script element from being included. When set to true the <script> element will not be included in the embed HTML, meaning that pages must include a reference to widgets.js manually. Defaults to false.
   * @param  string[optional] $align      Specifies whether the embedded Tweet should be left aligned, right aligned, or centered in the page. Valid values are left, right, center, and none. Defaults to none, meaning no alignment styles are specified for the Tweet.
   * @param  string[optional] $related    A value for the TWT related parameter, as described in Web Intents. This value will be forwarded to all Web Intents calls.
   * @param  string[optional] $lang       Language code for the rendered embed. This will affect the text and localization of the rendered HTML.
   * @return array
   */
  public function statusesOEmbed(
    $id = null, $url = null, $maxwidth = null, $hideMedia = null,
    $hideThread = null, $omitScript = null, $align = null, $related = null,
    $lang = null
   ) {
    if ($id == null && $url == null) {
      throw new Exception('Either id or url should be specified.');
    }

    // build parameters
    $parameters = null;
    if ($id != null) {
      $parameters['id'] = (string) $id;
    }
    if ($url != null) {
      $parameters['url'] = (string) $url;
    }
    if ($maxwidth != null) {
      $parameters['maxwidth'] = (int) $maxwidth;
    }
    if ($hideMedia !== null) {
      $parameters['hide_media'] = ($hideMedia) ? 'true' : 'false';
    }
    if ($hideThread !== null) {
      $parameters['hide_thread'] = ($hideThread) ? 'true' : 'false';
    }
    if ($omitScript !== null) {
      $parameters['omit_script'] = ($omitScript) ? 'true' : 'false';
    }
    if ($align != null) {
      $parameters['align'] = (string) $align;
    }
    if ($related != null) {
      $parameters['related'] = (string) $related;
    }
    if ($lang != null) {
      $parameters['lang'] = (string) $lang;
    }

    // make the call
    return (array) $this->doCall(
      'statuses/oembed.json',
      $parameters
    );
  }

  /**
   * Returns an HTTP 200 OK response code and a representation of the requesting user if authentication was successful; returns a 401 status code and an error message if not. Use this method to test if supplied user credentials are valid.
   *
   * @param  bool[optional] $includeEntities The entities node will not be included when set to false.
   * @param  bool[optional] $skipStatus      When set to true, statuses will not be included in the returned user objects.
   * @return array
   */
  public function accountVerifyCredentials(
      $includeEntities = null, $skipStatus = null
   ) {
    // build parameters
    $parameters = null;
    if ($includeEntities !== null) {
      $parameters['include_entities'] = ($includeEntities) ? 'true' : 'false';
    }
    if ($skipStatus !== null) {
      $parameters['skip_status'] = ($skipStatus) ? 'true' : 'false';
    }

    // make the call
    return (array) $this->doCall(
      'account/verify_credentials.json', $parameters, true
    );
  }

  /**
   * Updates the authenticating user's profile background image.
   *
   * @return array
   * @param  string         $image           The path to the background image for the profile. Must be a valid GIF, JPG, or PNG image of less than 800 kilobytes in size. Images with width larger than 2048 pixels will be forceably scaled down.
   * @param  bool[optional] $tile            Whether or not to tile the background image. If set to true the background image will be displayed tiled. The image will not be tiled otherwise.
   * @param  bool[optional] $includeEntities When set to true each tweet will include a node called "entities,". This node offers a variety of metadata about the tweet in a discreet structure, including: user_mentions, urls, and hashtags.
   */
  public function accountUpdateProfileBackgroundImage($image, $tile = false, $includeEntities = null ) {
    // validate
    if (!file_exists($image)) {
      throw new Exception('Image (' . $image . ') doesn\'t exists.');
    }

    // build parameters
    $parameters = null;
    if($tile) $parameters['tile'] = 'true';
    if ($includeEntities !== null) {
      $parameters['include_entities'] = ($includeEntities) ? 'true' : 'false';
    }

    // make the call
    return (array) $this->doCall(
      'account/update_profile_background_image.json',
      $parameters, true, 'POST', $image
    );
  }

// OAuth resources
  /**
   * Allows a Consumer application to use an OAuth request_token to request user authorization. This method is a replacement fulfills Secion 6.2 of the OAuth 1.0 authentication flow for applications using the Sign in with Twitter authentication flow. The method will use the currently logged in user as the account to for access authorization unless the force_login parameter is set to true
   * REMARK: This method seems not to work    @later
   *
   * @param bool[optional] $force Force the authentication.
   */
  public function oAuthAuthenticate($force = false ) {
    throw new Exception('Not implemented');

    // build parameters
    $parameters = null;
    if((bool) $force) $parameters['force_login'] = 'true';

    // make the call
    return $this->doCall('/oauth/authenticate.oauth', $parameters);
  }

  /**
   * Will redirect to the page to authorize the applicatione
   *
   * @param string $token The token.
   */
  public function oAuthAuthorize($token ) {
    header('Location: ' . self::SECURE_API_URL .
           '/oauth/authorize?oauth_token=' . $token);
  }

  /**
   * Allows a Consumer application to exchange the OAuth Request Token for an OAuth Access Token.
   * This method fulfills Secion 6.3 of the OAuth 1.0 authentication flow.
   *
   * @param  string $token    The token to use.
   * @param  string $verifier The verifier.
   * @return array
   */
  public function oAuthAccessToken($token, $verifier ) {
    // init var
    $parameters = array();
    $parameters['oauth_token'] = (string) $token;
    $parameters['oauth_verifier'] = (string) $verifier;

    // make the call
    $response = $this->doOAuthCall('access_token', $parameters);

    // set some properties
    if (isset($response['oauth_token'])) {
      $this->setOAuthToken($response['oauth_token']);
    }
    if (isset($response['oauth_token_secret'])) {
      $this->setOAuthTokenSecret($response['oauth_token_secret']);
    }

    // return
    return $response;
  }

  /**
   * Allows a Consumer application to obtain an OAuth Request Token to request user authorization.
   * This method fulfills Secion 6.1 of the OAuth 1.0 authentication flow.
   *
   * @param  string[optional] $callbackURL The callback URL.
   * @return array            An array containg the token and the secret
   */
  public function oAuthRequestToken($callbackURL = null ) {
    // init var
    $parameters = null;

    // set callback
    if ($callbackURL != null) {
      $parameters['oauth_callback'] = (string) $callbackURL;
    }

    // make the call
    $response = $this->doOAuthCall('request_token', $parameters);

    // validate
    if (!isset($response['oauth_token'], $response['oauth_token_secret'])) {
      throw new Exception(implode(', ', array_keys($response)));
    }

    // set some properties
    if (isset($response['oauth_token'])) {
      $this->setOAuthToken($response['oauth_token']);
    }
    if (isset($response['oauth_token_secret'])) {
      $this->setOAuthTokenSecret($response['oauth_token_secret']);
    }

    // return
    return $response;
  }

// Help resources
  /**
   * Returns the current configuration used by Twitter including twitter.com slugs which are not usernames, maximum photo resolutions, and t.co URL lengths.
   * It is recommended applications request this endpoint when they are loaded, but no more than once a day.
   *
   * @return array
   */
  public function helpConfiguration( ) {
    // make the call
    return $this->doCall(
      'help/configuration.json'
    );
  }

  /**
   * Returns the list of languages supported by Twitter along with their ISO 639-1 code. The ISO 639-1 code is the two letter value to use if you include lang with any of your requests.
   *
   * @return array
   */
  public function helpLanguages( ) {
    // make the call
    return $this->doCall(
      'help/languages.json'
    );
  }

  /**
   * Returns Twitter's Privacy Policy
   *
   * @return array
   */
  public function helpPrivacy( ) {
    // make the call
    return $this->doCall(
      'help/privacy.json'
    );
  }

  /**
   * Returns the Twitter Terms of Service in the requested format. These are not the same as the Developer Rules of the Road.
   *
   * @return array
   */
  public function helpTos( ) {
    // make the call
    return $this->doCall(
      'help/tos.json'
    );
  }

  /**
   * Returns the current rate limits for methods belonging to the specified resource families.
   * Each 1.1 API resource belongs to a "resource family" which is indicated in its method documentation. You can typically determine a method's resource family from the first component of the path after the resource version.
   * This method responds with a map of methods belonging to the families specified by the resources parameter, the current remaining uses for each of those resources within the current rate limiting window, and its expiration time in epoch time. It also includes a rate_limit_context field that indicates the current access token context.
   * You may also issue requests to this method without any parameters to receive a map of all rate limited GET methods. If your application only uses a few of methods, please explicitly provide a resources parameter with the specified resource families you work with.
   *
   * @param  array  $resources A comma-separated list of resource families you want to know the current rate limit disposition for. For best performance, only specify the resource families pertinent to your application.
   * @return string
   */
  public function applicationRateLimitStatus(array $resources = null ) {
    $parameters = null;
    if (!empty($resources)) {
      $parameters['resources'] = implode(',', $resources);
    }

    // make the call
    return $this->doCall(
      'application/rate_limit_status.json',
      $parameters
    );
  }
}
