# XLayer AI - AI-Powered Cybersecurity Platform

This repository contains the source code for the XLayer AI website, a course project demonstrating a modern, responsive frontend built with React and Tailwind CSS, and a backend API powered by Python and Flask.

## Project Overview

XLayer AI is a fictional cybersecurity platform focused on ethical hacking, threat intelligence, and vulnerability analysis. The website showcases the platform’s mission and its suite of AI-driven tools. The key feature is an integrated AI chatbot (powered by the "XLayer Intelligence Core" or XIC) that allows users to interact with the platform in real-time.

-   **Live Frontend Demo:** [Link to your GitHub Pages URL]
-   **Live Backend API:** [Link to your Render URL]

### Tech Stack

-   **Frontend:**
    -   **React:** For building a dynamic, component-based user interface.
    -   **React Router:** For client-side routing and navigation between pages.
    -   **Tailwind CSS:** For rapid, utility-first styling and a responsive design.
    -   **Deployment:** GitHub Pages

-   **Backend:**
    -   **Python Flask:** A lightweight web framework to create the backend API.
    -   **Flask-CORS:** To handle cross-origin requests from the frontend.
    -   **Deployment:** Render (Free Tier)

-   **Development Tools:**
    -   **Version Control:** Git & GitHub
    -   **IDE:** VSCode / Cursor

### Features

-   **Responsive Design:** Fully optimized for desktop, tablet, and mobile devices.
-   **Interactive AI Chatbot:** A ChatGPT-style assistant connected to a live backend API.
-   **Multi-Page Layout:** Includes Home, About, Tools, Vision, Blog, and Contact pages.
-   **Modern UI/UX:** Sleek dark mode with a "hacker" aesthetic using blue and purple accents.
-   **API Integration:** The chatbot and contact form communicate with the Flask backend.

---

## How to Run Locally

### 1. Backend (Flask Server)

1.  **Navigate to the backend directory:**
    ```bash
    cd backend
    ```
2.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Run the server:**
    ```bash
    flask run --port 5001
    ```
    The backend is now running at `http://127.0.0.1:5001`.

### 2. Frontend (React App)

1.  Open a new terminal and navigate to the `frontend` directory.
2.  Since we are not using a Node.js build step, you need a simple HTTP server to serve the files. The easiest way is with Python.
    ```bash
    # If you have Python 3
    python -m http.server 8000
    ```
3.  Open your web browser and go to: `http://localhost:8000`. The website should be fully functional, but the chatbot will fail to connect because it's pointing to the production Render URL.
    -   **For local testing:** Temporarily change the `fetch` URL in `frontend/components/Chatbot.jsx` from the Render URL to `http://127.0.0.1:5001/api/chat`.

---

## Deployment

### 1. Deploying the Backend to Render

1.  Push your project to a GitHub repository.
2.  Go to [Render.com](https://render.com/) and create a new "Web Service".
3.  Connect your GitHub repository.
4.  Configure the service:
    -   **Name:** `xlayer-ai-backend` (or similar)
    -   **Root Directory:** `backend`
    -   **Environment:** `Python 3`
    -   **Build Command:** `pip install -r requirements.txt`
    -   **Start Command:** `gunicorn server:app` (Gunicorn is a production-ready server)
5.  Click "Create Web Service". Render will deploy your API. Once it's live, copy the URL (e.g., `https://xlayer-ai-backend.onrender.com`).

### 2. Deploying the Frontend to GitHub Pages

1.  **Update API URL:** Go to `frontend/components/Chatbot.jsx` and make sure the `fetch` URL points to your new **Render URL**.
    ```javascript
    const response = await fetch('https://YOUR_RENDER_URL/api/chat', { ... });
    ```
2.  Commit and push this change to your GitHub repository.
3.  In your GitHub repo, go to **Settings > Pages**.
4.  Under "Build and deployment", select the source as **"Deploy from a branch"**.
5.  Choose the branch (e.g., `main`) and the folder (`/frontend`) and click **Save**.
6.  GitHub will deploy your site. The URL will be available on the same page after a few minutes.

## Challenges & Solutions

-   **Challenge:** Integrating a React frontend (typically Node.js-based) with a Python backend without a complex build setup.
    -   **Solution:** Used CDN links for React and Babel, allowing JSX to be transpiled directly in the browser. This simplifies the setup for a course project, avoiding the need for Webpack/Vite.
-   **Challenge:** Handling Cross-Origin Resource Sharing (CORS) between the frontend on GitHub Pages and the backend on Render.
    -   **Solution:** Implemented the `Flask-CORS` library on the backend to explicitly allow requests from any origin, making the API accessible to the deployed frontend.