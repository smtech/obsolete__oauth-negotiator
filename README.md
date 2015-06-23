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

When you would like to acquire a token, the easiest use of this is to provide three pages:

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
  
  // get the user informatio associated with that token
  print_r($oauth->getUser());
?>
```

Complete documentation is [in the package online](https://htmlpreview.github.io?https://github.com/smtech/oauth-negotiator/blob/master/.gitignore).
