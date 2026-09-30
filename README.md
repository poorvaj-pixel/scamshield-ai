# ScamShield AI

ScamShield AI is a Flask web app for reviewing suspicious messages, links, screenshots, and conversations. It combines local rule-based checks with optional OpenAI analysis to explain potential scam indicators and suggest safer next steps.

> Scam detection is heuristic and can be wrong. A low score does not prove a message is safe. Verify unexpected requests through an official, independent channel.

## Features

- Analyze message text and URLs for common phishing and social-engineering signals.
- Review a conversation as a sequence, including escalation across up to 20 messages.
- Extract text from screenshots in the browser with Tesseract.js, then analyze the extracted text.
- Optionally transcribe call recordings with OpenAI. Supported formats are MP3, WAV, M4A, WEBM, MP4, MPEG, and MPGA; the upload limit is 25 MB.
- View scan results, risk reasons, and local activity history in the browser.

## Requirements

- Python 3.9 or later
- pip
- An OpenAI API key is optional. Without one, local message and conversation analysis remain available; AI-generated message analysis and call transcription require the key.

## Run locally

Create and activate a virtual environment from the repository root.

**Windows PowerShell**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS or Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

For OpenAI features, create a `.env` file in the repository root:

```dotenv
OPENAI_API_KEY=your_openai_api_key
```

The key is optional. Keep `.env` private and do not commit it. Then start the development server:

```bash
python app.py
```

Open <http://127.0.0.1:5000>.

## Deploy to Render

The included `render.yaml` configures a Python web service with `pip install -r requirements.txt` as its build command and `gunicorn app:app` as its start command.

1. In Render, create a Blueprint from this GitHub repository and apply the `render.yaml` configuration.
2. To enable OpenAI analysis and call transcription, add `OPENAI_API_KEY` in the service's environment settings. Store it as a secret; do not add it to the repository.
3. Deploy the service. Without the key, local rule-based message and conversation analysis still works.

## HTTP API

### `GET /api/health`

Returns service status and whether an OpenAI client was initialized:

```json
{"status":"online","python_ai":false}
```

### `POST /api/analyze`

Send JSON with a `message` string (maximum 10,000 characters):

```json
{"message":"Your account will be suspended. Verify your details now."}
```

The response includes `risk_score`, `risk_level`, `signals`, `category`, `reasons`, `urls_found`, `recommendation`, and `ai_analysis`.

### `POST /api/analyze_conversation`

Send a `messages` array with up to 20 entries. Each entry can contain `sender` and `text`:

```json
{
  "messages": [
    {"sender":"Unknown","text":"I can help with your account."},
    {"sender":"Unknown","text":"Send me the verification code now."}
  ]
}
```

The response includes an overall risk level and score, a per-message timeline, and an escalation path.

### `POST /api/transcribe_call`

Send `multipart/form-data` with the recording in the `audio` field. Requires `OPENAI_API_KEY`; requests without an initialized OpenAI client return `503`.

## Data and privacy

- Screenshot OCR runs in the browser. The screenshot itself is not uploaded to this Flask app; the extracted text is sent to the app for analysis.
- When `OPENAI_API_KEY` is configured, message text may be sent to OpenAI for AI analysis. Call recordings sent to `/api/transcribe_call` are sent to OpenAI for transcription.
- Browser scan history and settings are stored in that browser's `localStorage`; they are not shared across browsers.
- Tesseract.js is loaded from a public CDN, with a fallback CDN configured in the page.

## Project layout

```text
.
|-- app.py
|-- render.yaml
|-- requirements.txt
|-- templates/
|   `-- index.html
`-- README.md
```