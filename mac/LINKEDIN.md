# LinkedIn agent: setup (about 10 minutes, once)

The agent drafts posts from your analyst notes or daily brief, checks them, and sends the draft
to Telegram. **Nothing is posted until you run `publish` and type `y`.**

## 1. Create a LinkedIn app (free, self-serve)
1. Go to https://www.linkedin.com/developers/apps and choose **Create app**. LinkedIn asks for a
   Company Page to associate the app with; create a free page for "Watchfloor" if you have none.
2. On the **Products** tab, add **Share on LinkedIn** and **Sign In with LinkedIn using OpenID Connect**.
3. On the **Auth** tab, add the redirect URL `http://localhost:8766/callback`.
4. Copy the **Client ID** and **Client Secret**.

## 2. Save the keys and sign in
```
cd ~/watchfloor && git pull --rebase
./mac/setup.sh                 # press Enter past saved keys; paste the LinkedIn ID and Secret
./mac/linkedin.sh auth         # a browser opens; approve; the token goes to Keychain
```
The token lasts 60 days. `./mac/linkedin.sh status` shows when to sign in again.

## 3. Use it
```
./mac/linkedin.sh draft --from note     # latest analyst note
./mac/linkedin.sh draft --from brief    # today's brief
./mac/linkedin.sh list
./mac/linkedin.sh judge ID              # re-run the judge after editing a draft
./mac/linkedin.sh publish ID            # judge, open the image, show the post, ask before publishing
```
Replace `ID` with the id the draft command prints (no angle brackets: zsh reads `<` as a redirect).
Drafts and their images are stored in `~/.watchfloor/linkedin/` (not in the public repo). To change a
draft, edit its `text` field in that JSON file, then run `judge` or `publish` again.

## The image
Every draft from a note gets a 1080x1350 branded image with the theparijat.com watermark. What it says
comes from the note's `visual:` front-matter block (title, a numbered chain of steps if the note has a
real sequence, up to three figures marked confirmed or reported). A note without one gets a title card.
The image is drawn by code, not an image model, so it cannot add a fact the note does not contain.

## The judge
Before the publish prompt, the judge checks the post and the image text against the source:
1. Facts: every CVE id, version, percentage and number must appear in the source.
2. Review: a second model (never the one that drafted) reports unsupported or overstated claims,
   dropped caveats, incomplete fix steps and ambiguous sentences.

A FAIL blocks publishing. If no second model answers, publishing is blocked unless you add
`--skip-judge` after checking the post yourself. A PASS does not publish: you still type `y`.

## Checks every draft must pass
- 3,000 characters or fewer; contains the link to the note or brief
- only links that appear in the source
- no employer or client names (`linkedin.never_name` in config.yaml)
- no banned phrases; at most five hashtags

Check your employer's social media policy before posting about security topics.
