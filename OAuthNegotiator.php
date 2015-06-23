<?php
	
/**
 * Conduct negotiations with Canvas for an OAuth token
 *
 * @version GIT: $Id$
 * @author Seth Battis <SethBattis@stmarksschool.org>
 **/
class OAuthNegotiator {

	const STATE = 'state';
		const API_TOKEN = 0;
		const DEFAULT_SCOPE = self::API_TOKEN;
		const IDENTITY_TOKEN = '/auth/userinfo/';
		const CODE_REQUESTED = 'CODE_REQUESTED';
		const CODE_PROVIDED = 'CODE_PROVIDED';
		const TOKEN_REQUESTED = 'TOKEN_REQUESTED';
		const TOKEN_PROVIDED = 'TOKEN_PROVIDED';
		const NEGOTIATION_COMPLETE = 'NEGOTIATION_COMPLETE';
		const NEGOTIATION_FAILED = 'NEGOTIATION_FAILED';

	private static $SCOPES = array(
		/* request API token */
		self::API_TOKEN => array(
			self::CODE_REQUESTED => '63825fcbcad21e1427a18d5d258e1296',
			self::CODE_PROVIDED => 'b6836b4d7e23e78a5748194a3d65950d',
			self::TOKEN_REQUESTED => '199258f8a5a950c040239edd1127df26',
			self::TOKEN_PROVIDED => 'cdc951d7d6b7a7b7a45c10b37c129764'
		),
		
		/* authenticate identity only */
		self::IDENTITY_TOKEN => array(
			self::CODE_REQUESTED => 'd0601ee3ec02a7bf4627e87afb906f50',
			self::CODE_PROVIDED => '60e1d51d16294c0f730cef1b1f3bb7bd',
			self::TOKEN_REQUESTED => '91e37933ff5487415eb2d4677e6a707d',
			self::TOKEN_PROVIDED => '160d7e0089b7c481d7a3a7a124277ead'
		)
	);
	
	const SESSION = 'OAuthNegotiator';
		const OAUTH_ENDPOINT = 'OAUTH_ENDPOINT';
		const API_ENDPOINT = 'API_ENDPOINT';
		const CLIENT_ID = 'client_id';
		const CLIENT_SECRET = 'client_secret';
		const CODE = 'code';
		const ERROR = 'ERROR';
		const RESPONSE_TYPE = 'response_type';
		const REDIRECT_URI = 'redirect_uri';
		const SCOPES = 'scopes';
		const LANDING_PAGE = 'landing_page';
		const PURPOSE = 'purpose';
		const SCOPE = 'scope';
		const IDENTITY = 'IDENTITY';
		const API = 'API';
		const TOKEN = 'TOKEN';
		const USER = 'USER';
	
	/**
	 * @var boolean $ready Is the token ready yet?
	 **/
	private $ready = false;
	
	/**
	 * @var string $token The token provided via OAuth
	 **/
	private $token = null;
	
	/**
	 * @var array|null $user The user data associated with the API access token (no user for an identity token... go figure)
	 **/
	private $user = null;
	
	/**
	 * @var string|null $error Any errors returned explaining why we might be "ready" but not have a token
	 **/
	private $error = null;

	/**
	 * Construct OAuthNegotiator to start (or continue) OAuth authentication negotiations
	 *
	 * @param string $OAuthEndpoint optional URI of the OAuth authentication endpoint (e.g. 'https://<canvas-install-url>/login/oauth2') -- REQUIRED on first instantiation
	 * @param string $clientId optional A unique client ID for the application requesting authentication (usually some terrible hash or serial number) -- REQUIRED on first instantiation
	 * @param string $clientSecret optional A shared secret key between this application and the OAuth server -- REQUIRED on first instantiation
	 * @param string $landingPage optional URI to land at after OAuth is negotiated (defaults to $_SERVER[PHP_SELF])
	 * @param string $purpose optional How this authentication token will be used (defaults to $_SERVER[PHP_SELF])
	 * @param string $APIEndpoint optional URI of the API endpoint (e.g. 'https://<canvas-install-url>/api/vi', defaults to str_replace('/login/oauth2', '/api/v1', $OAuthEndpoint))
	 * @param string $scopes optional The scope of this authentication (defaults to API token request)
	 * @param string $responseType optional Type of response expected from OAuth server (defaults to 'code')
	 * @param string $redirectUri optional URI to handle OAuth server response (defaults to $_SERVER[PHP_SELF])
	 *
	 * @return void
	 *
	 * @throws OAuthNegotiator_Exception OAUTH_ENDPOINT if $OAuthEndpoint is empty or not provided
	 * @throws OAuthNegotiator_Exception CLIENT_ID if $clientId is empty or not provided
	 * @throws OAuthNegotiator_Exception CLIENT_SECRET if $clientSecret is  empty or not provided
	 *
	 * @throws OAuthNegotiator_Exception STATE_MISMATCH if $_REQUEST[state] does not align with $_SESSION[SESSION][STATE]
	 **/
	public function __construct($OAuthEndpoint, $clientId, $clientSecret, $landingPage = false, $purpose = null, $APIEndpoint = false, $scopes = self::DEFAULT_SCOPE, $responseType = 'code', $redirectURI = null) {
		
		/* start our session (if it has not already been started) */
		switch (session_status()) {
			case PHP_SESSION_DISABLED:
				throw new OAuthNegotiator_Exception(
					'Cannot negotiate for OAuth authentication without sessions',
					OAuthNegotiator_Exception::SESSION_STATUS
				);
				break;
			case PHP_SESSION_NONE:
				session_start();
		}
				
		if (isset($_SESSION[self::SESSION][self::STATE])) {
			switch ($_SESSION[self::SESSION][self::STATE]) {
				case self::$SCOPES[self::API_TOKEN][self::CODE_REQUESTED]: {
					if ($_REQUEST[self::STATE] === self::$SCOPES[self::API_TOKEN][self::CODE_PROVIDED]) {
						call_user_func_array(array($this, 'constructAPIToken'), func_get_args());
					} else {
						throw new OAuthNegotiator_Exception(
							"State mismatch (received '{$_REQUEST['state']}', expected '" . self::$SCOPES[self::API_TOKEN][self::CODE_REQUESTED] . ')',
							OAuthNegotiator_Exception::STATE_MISMATCH
						);
					}
					break;
				}
				case self::$SCOPES[self::IDENTITY_TOKEN][self::CODE_REQUESTED]: {
					if ($_REQUEST[self::STATE] === self::$SCOPES[self::IDENTITY_TOKEN][self::CODE_PROVIDED]) {
						call_user_func_array(array($this, 'constructIdentityToken'), func_get_args());
					} else {
						throw new OAuthNegotiator_Exception(
							"State mismatch (received '{$_REQUEST['state']}', expected '" . self::$SCOPES[self::IDENTITY_TOKEN][self::CODE_REQUESTED] . ')',
							OAuthNegotiator_Exception::STATE_MISMATCH
						);
					}
				}
				case self::NEGOTIATION_COMPLETE:
				case self::NEGOTIATION_FAILED: {
					$this->constructNegotiationReporter($_SESSION[self::SESSION][self::STATE]);
					break;
				}
			}		
		} else {
			call_user_func_array(array($this, 'constructStateless'), func_get_args());
		}
	}

	/**
	 * Construct a "stateless" (i.e. unstarted) OAuthNegotiator
	 *
	 * @param string $OAuthEndpoint URI of the OAuth authentication endpoint (e.g. 'https://<canvas-install-url>/login/oauth2')
	 * @param string $clientId A unique client ID for the application requesting authentication (usually some terrible hash or serial number)
	 * @param string $clientSecret A shared secret key between this application and the OAuth server
	 * @param string $landingPage optional URI to land at after OAuth is negotiated (defaults to $_SERVER[PHP_SELF])
	 * @param string $purpose optional How this authentication token will be used (defaults to $_SERVER[PHP_SELF])
	 * @param string $APIEndpoint optional URI of the API endpoint (e.g. 'https://<canvas-install-url>/api/vi', defaults to str_replace('/login/oauth2', '/api/v1', $OAuthEndpoint))
	 * @param string $scopes optional The scope of this authentication (defaults to API token request)
	 * @param string $responseType optional Type of response expected from OAuth server (defaults to 'code')
	 * @param string $redirectUri optional URI to handle OAuth server response (defaults to $_SERVER[PHP_SELF])
	 *
	 * @throws OAuthNegotiator_Exception OAUTH_ENDPOINT if $OAuthEndpoint is empty or not provided
	 * @throws OAuthNegotiator_Exception CLIENT_ID if $clientId is empty or not provided
	 * @throws OAuthNegotiator_Exception CLIENT_SECRET if $clientSecret is  empty or not provided
	 **/
	private function constructStateless($OAuthEndpoint, $clientId, $clientSecret, $landingPage = false, $purpose = null, $APIEndpoint = false, $scopes = self::DEFAULT_SCOPE, $responseType = 'code', $redirectURI = null) {

		if (isset($OAuthEndpoint) && !empty($OAuthEndpoint)) {
			$_SESSION[self::SESSION][self::OAUTH_ENDPOINT] = $OAuthEndpoint;
		} else {
			throw new OAuthNegotiator_Exception(
				'Missing OAuth endpoint URI.',
				OAuthNegotiator_Exception::OAUTH_ENDPOINT
			);
		}
		
		if (isset($clientId) && !empty($clientId)) {
			$_SESSION[self::SESSION][self::CLIENT_ID] = $clientId;
		} else {
			throw new OAuthNegotiator_Exception(
				'Missing client ID.',
				OAuthNegotiator_Exception::CLIENT_ID
			);
		}
		
		if (isset($clientSecret) && !empty($clientSecret)) {
			$_SESSION[self::SESSION][self::CLIENT_SECRET] = $clientSecret;
		} else {
			throw new OAuthNegotiator_Exception(
				"Missing client secret",
				OAuthNegotiator_Exception::CLIENT_SECRET
			);
		}
		
		if ($landingPage === false) {
			$_SESSION[self::SESSION][self::LANDING_PAGE] = $_SERVER['PHP_SELF'];
		} else {
			$_SESSION[self::SESSION][self::LANDING_PAGE] = $landingPage;
		}
		
		if ($APIEndpoint === false) {
			$_SESSION[self::SESSION][self::API_ENDPOINT] = str_replace('/login/oauth2', '/api/v1', $_SESSION[self::SESSION][self::OAUTH_ENDPOINT]);
		} else {
			$_SESSION[self::SESSION][self::API_ENDPOINT] = $APIEndpoint;
		}
		
		if (!isset($redirectURI)) {
			$_SESSION[self::SESSION][self::REDIRECT_URI] = (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] != 'on' ? 'http://' : 'https://') . $_SERVER['SERVER_NAME'] . $_SERVER['PHP_SELF'];
		} else {
			$_SESSION[self::SESSION][self::REDIRECT_URI] = $redirectURI;
		}
		
		if (!isset($purpose)) {
			$purpose = $_SERVER['PHP_SELF'];
		}
				
		$this->requestAuthorizationCode($responseType, $scopes, $purpose);
	}
	
	/**
	 * Construct an OAuthNegotiator to use an access code to request an identity token
	 *
	 * @return void
	 *
	 * @throws OAuthNegotiator_Exception CODE_RESPONSE if the prior request for an authorization token resulted in neither an authorization code or an erro (weird!)
	 **/
	private function constructIdentityToken() {
		if (isset($_REQUEST[self::CODE])) {
			$this->requestToken($_REQUEST[self::CODE], self::IDENTITY_TOKEN);
			$_SESSION[self::SESSION][self::STATE] = self::NEGOTIATION_COMPLETE;
			header("Location: {$_SESSION[self::SESSION][self::LANDING_PAGE]}");
			exit;
		} elseif (isset($_REQUEST[self::ERROR])) {
			$_SESSION[self::SESSION][self::STATE] = self::NEGOTIATION_FAILED;
			$_SESSION[self::SESSION][self::ERROR] = $_REQUEST[self::ERROR];
			header("Location: {$_SESSION[self::SESSION][self::LANDING_PAGE]}?error={$_REQUEST[self::ERROR]}");
			exit;
		} else {
			throw new OAuthNegotiator_Exception(
				'Unexpected OAuth response',
				OAuthNegotiator_Exception::CODE_RESPONSE
			);
		}
	}
	
	/**
	 * Construct an OAuthNegotiator to use an access code to request an API Token with matching user profile
	 *
	 * @return void
	 *
	 * @throws OAuthNegotiator_Exception CODE_RESPONSE if the prior request for an authorization token resulted in neither an authorization code or an error (weird!)
	 * @throws OAuthNegotatior_Exception USER_RESPONSE if a user profile cannot be acquired to match the API access token (i.e. the OAuth server is probably not a Canvas instance)
	 **/
	private function constructAPIToken() {
		if (isset($_REQUEST[self::CODE])) {
			$this->requestToken($_REQUEST[self::CODE], self::API_TOKEN);
			$api = new CanvasPest($_SESSION[self::SESSION][self::API_ENDPOINT], $_SESSION[self::SESSION][self::TOKEN]);
			if ($response = $api->get('/users/self/profile')) {
				$_SESSION[self::SESSION][self::USER] = $response;
			} else {
				throw new OAuthNegotiator_Exception(
					'Failed to get user profile',
					OAuthNegotiator_Exception::USER_RESPONSE
				);
			}
			$_SESSION[self::SESSION][self::STATE] = self::NEGOTIATION_COMPLETE;
			header ("Location: {$_SESSION[self::SESSION][self::LANDING_PAGE]}");
			exit;
		} elseif (isset($_REQUEST[self::ERROR])) {
			$_SESSION[self::SESSION][self::STATE] = self::NEGOTIATION_FAILED;
			$_SESSION[self::SESSION][self::ERROR] = $_REQUEST[self::ERROR];
			header("Location: {$_SESSION[self::SESSION][self::LANDING_PAGE]}?error={$_REQUEST[self::ERROR]}");
			exit;
		} else {
			throw new OAuthNegotiator_Exception(
				'Unexpected OAuth response',
				OAuthNegotiator_Exception::CODE_RESPONSE
			);
		}
		
	}
	
	/**
	 * Prepare to report on the results of the OAuth negotiation
	 *
	 * @return void
	 **/
	private function constructNegotiationReporter() {
		switch ($_SESSION[self::SESSION][self::STATE]) {
			case self::NEGOTIATION_COMPLETE:
			case self::NEGOTIATION_FAILED: {
				$this->ready = true;
				$this->token = (isset($_SESSION[self::SESSION][self::TOKEN]) ? $_SESSION[self::SESSION][self::TOKEN] : null);
				$this->user = (isset($_SESSION[self::SESSION][self::USER]) ? $_SESSION[self::SESSION][self::USER] : null);
				$this->error = (isset($_SESSION[self::SESSION][self::ERROR]) ? $_SESSION[self::SESSION][self::ERROR] : null);
				unset($_SESSION[self::SESSION]);
				$_SESSION[self::SESSION][self::STATE] = $state;
				break;
			}
			default: {
				$this->ready = false;
			}
		}
	}
	
	/**
	 * Is the OAuth negotiation complete?
	 *
	 * @return boolean TRUE if negotiations have finished, FALSE if they are ongoing
	 **/
	public function isReady() {
		return $this->ready;
	}
	
	/**
	 * @return boolean TRUE if OAuth negoation is complete and resulted in an identy token (FALSE if negotiations are onging or the token is an API access token)
	 **/
	public function isIdentityToken() {
		if ($this->ready) {
			return !empty($this->token) && !is_array($this->user);
		} else {
			return false;
		}
	}
	
	/**
	 * @return boolean TRUE if OAuth negotation is complete and resulted in an API access token (FALSE if negotations are ongoing or the token is an identity token)
	 **/
	public function isAPIToken() {
		if ($this->ready) {
			return !empty($this->token) && is_array($this->user);
		} else {
			return false;
		}
	}
	
	/**
	 * @return string|boolean|null OAuth token (if any) if OAuth negotiation is complete (FALSE if ongoing)
	 **/
	public function getToken() {
		if ($this->ready) {
			return $this->token;
		} else {
			return false;
		}
	}
	
	/**
	 * @return array|boolean|null Associative array (if any) of user profile if OAuth negotiation is complete (FALSE if onging)
	 **/
	public function getUser() {
		if ($this->ready) {
			return $this->user;
		} else {
			return false;
		}
	}
	
	/**
	 * @return string|boolean|null Error (if any) that ended the OAuth negotiation (FALSE if negotiation is ongoing)
	 **/
	public function getError() {
		if ($this->ready) {
			return $this->error;
		} else {
			return false;
		}
	}
	
	/**
	 * Request an authorization code from the OAuth server
	 *
	 * @param string $responseType Always 'code'
	 * @param string $scopes The type of token for which we need an authorization code (IDENTITY_TOKEN|API_TOKEN)
	 * @param string $purpose User-readable description of the purpose for which this token will be used
	 *
	 * @return void
	 **/
	private function requestAuthorizationCode($responseType, $scopes, $purpose) {
		$_SESSION[self::SESSION][self::STATE] = self::$SCOPES[$scopes][self::CODE_REQUESTED];
		if ($scopes === self::IDENTITY_TOKEN) {
			header(
				"Location: {$_SESSION[self::SESSION][self::OAUTH_ENDPOINT]}/auth?" . http_build_query(
					array(
						self::CLIENT_ID => $_SESSION[self::SESSION][self::CLIENT_ID],
						self::RESPONSE_TYPE => $responseType,
						self::REDIRECT_URI => $_SESSION[self::SESSION][self::REDIRECT_URI],
						self::STATE => self::$SCOPES[$scopes][self::CODE_PROVIDED],
						self::SCOPES => $scopes,
						self::PURPOSE => $purpose
					)
				)
			);
		} else {
			header(
				"Location: {$_SESSION[self::SESSION][self::OAUTH_ENDPOINT]}/auth?" . http_build_query(
					array(
						self::CLIENT_ID => $_SESSION[self::SESSION][self::CLIENT_ID],
						self::RESPONSE_TYPE => $responseType,
						self::REDIRECT_URI => $_SESSION[self::SESSION][self::REDIRECT_URI],
						self::STATE => self::$SCOPES[$scopes][self::CODE_PROVIDED],
						self::PURPOSE => $purpose
					)
				)
			);
		}
		exit;
	}
	
	/**
	 * Request a token from the OAuth server
	 *
	 * @param string $code An authorization code provided by the OAuth server
	 * @param string $tokenType Type of token being requested (IDENTITY_TOKEN|API_TOKEN)
	 *
	 * @return void Updates session variables
	 *
	 * @throws OAuthNegotiator_Exception TOKEN_RESPONSE if a token no token is received or on any other uanticipated response from the OAuth server
	 **/
	private function requestToken($code, $tokenType) {
		$authApi = new PestJSON("{$_SESSION[self::SESSION][self::OAUTH_ENDPOINT]}");
		try {
			$response = $authApi->post('token',
				array(
					self::CLIENT_ID => $_SESSION[self::SESSION][self::CLIENT_ID],
					self::REDIRECT_URI => $_SESSION[self::SESSION][self::REDIRECT_URI],
					self::STATE => self::$SCOPES[$tokenType][self::TOKEN_PROVIDED],
					self::CLIENT_SECRET => $_SESSION[self::SESSION][self::CLIENT_SECRET],
					self::CODE => $code,
				)
			);
		} catch (Pest_ServerError $e) {
			echo $e->getMessage();
			exit;
		}
		if ($response) {
			if (isset($response['access_token'])) {
				$_SESSION[self::SESSION][self::TOKEN] = $response['access_token'];
				return true;
			} else {
				throw new OAuthNegotiator_Exception(
					'Access token not received',
					OAuthNegotiator_Exception::TOKEN_RESPONSE
				);
			}
		} else {
			throw new OAuthNegotiator_Exception(
				'Unexpected OAuth response',
				OAuthNegotiator_Exception::TOKEN_RESPONSE
			);
		}
	}
	
}

/**
 * Exceptions generated by OAuthNegotiator
 *
 * @version GIT: $Id$
 * @author Seth Battis <SethBattis@stmarksschool.org>
 **/
class OAuthNegotiator_Exception extends Exception {
	const OAUTH_ENDPOINT = 1;
	const CLIENT_ID = 2;
	const CLIENT_SECRET = 3;
	const STATE_MISMATCH = 4;
	const CODE_RESPONSE = 5;
	const TOKEN_RESPONSE = 6;
	const USER_RESPONSE = 7;
	const NOT_READY = 8;
}
	
?>