# OAuthNegotiator

I find it difficult to wrap my head around negotiating for OAuth tokens -- and I would prefer not to have to think about it.
This is particularly focused on negotiating with _Instructure Canvas_ for OAuth tokens, to be sure.

### Usage

Include in your `composer.json` file:

```JSON
{
  "requires" : {
    "smtech/oauth-negotiator": "1.0"
  }
}
```

When you would like to acquire a token, the easiest use of this is to provide three pages (keep reading for a single page variant):

#### page1.php

```HTML
<html>
  <body>
    <form action="page2.php" method="post">
      <label>Enter the URL of your canvas instance</label>
      <input type="text" name="url" placeholder="https://canvas.instructure.com" />
      <input type="submit" value="Negotiate!" />
    </form>
  </body>
</html>
```

#### page2.php

`page2.php` will be re-loaded several times throughout the negotiation, so it's easiest to simply isolate this part of the 
negotiation on its own page and redirect in and out of that page.

```PHP
<?php
  $oauth = new OAuthNegotiator(
    $_REQUEST['url'] . '/login/oauth2',
    '0000000001', // Canvas developer ID
    '6987c1e292a98deff97c97f2cbc49985', // Canvas developer key/secret (referred to both ways in their documentation)
    'page3.php', // where to go when we're done
    'OAuthNegotiator' // your purpose for this token (displayed on the user settings page in Canvas)
  );
?>
```

#### page3.php

```PHP
<?php
  $oauth = new OAuthNegotiator();
  
  // get your token
  echo $oauth->getToken();
  
  // get the user information associated with that token
  print_r($oauth->getUser());
?>
```
###Single Page Usage

```PHP
/* attempt to create a simple OAuthNegotiator for the intermediate steps in the workflow */
try {
	$oauth = new OAuthNegotiator();
} catch (OAuthNegotiator_Exception $e) {}

/* otherwise, check what step in the workflow we're at */
if (isset($_REQUEST['oauth'])) {
	switch ($_REQUEST['oauth']) {
		case 'request': { // explain what's up to the user
			echo '
<html>
	<body>
		<h1>Token Request</h1>
		<p>Explain why you're requesting a token.</p>
		<p><a href="' . $_SERVER['PHP_SELF'] . '?oauth=process">Click to continue</a></p>
	</body>
</html>';
			exit;
		}
		case 'process': { // start the negotiation process
			$oauth = new OAuthNegotiator(
				"https://canvas.instructure.com/login/oauth2", // replace with your OAuth provider endpoint
				(string) $secrets->oauth->id,
				(string) $secrets->oauth->key,
				"{$_SERVER['PHP_SELF']}?oauth=complete",
				(string) $secrets->app->name
			);
			break;
		}
		case 'complete': { // negotiation is complete
			/* do something productive with your token */
			$_SESSION['apiToken'] = $oauth->getToken();

      /* on to the next page, token in hand! */
			header("Location: ./next.php");
			exit;
		}
	}
}
```

Complete documentation is [in the package online](https://htmlpreview.github.io?https://github.com/smtech/oauth-negotiator/blob/master/doc/index.html).
