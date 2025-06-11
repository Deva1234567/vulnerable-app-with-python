
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Broken Authentication</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link href="{{ url_for('static', filename='css/style.css') }}" rel="stylesheet">
    <link rel="icon" type="image/x-icon" href="{{ url_for('static', filename='favicon.ico') }}">
    <style>
        body.modal-open {
            overflow: hidden;
        }
        #solution-modal, #hint-modal {
            position: fixed;
            inset: 0;
            background-color: rgba(0, 0, 0, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 50;
            overflow: auto;
            padding: 1rem;
        }
        .modal-content {
            max-height: 90vh;
            overflow-y: auto;
        }
        html.light {
            background-color: #f3f4f6;
        }
        html.light .dark\:bg-gray-900 {
            background-color: #ffffff;
        }
        html.light .dark\:bg-gray-800 {
            background-color: #f9fafb;
        }
        html.light .dark\:text-gray-200 {
            color: #1f2937;
        }
        html.light .dark\:text-gray-400 {
            color: #4b5563;
        }
        html.light .dark\:text-green-300 {
            color: #15803d;
        }
        html.light .dark\:text-red-400 {
            color: #dc2626;
        }
        html.light .dark\:bg-green-900 {
            background-color: #dcfce7;
        }
        html.light .dark\:border-green-500 {
            border-color: #22c55e;
        }
        html.light .dark\:text-blue-400 {
            color: #2563eb;
        }
        html.light .dark\:bg-gray-700 {
            background-color: #e5e7eb;
        }
        html.light .dark\:text-yellow-400 {
            color: #d97706;
        }
    </style>
</head>
<body class="min-h-screen flex flex-col">
    <nav class="navbar">
        <div class="navbar-container flex flex-col items-center">
            <h1 class="text-2xl font-semibold text-white dark:text-gray-200 mb-4 text-center">Vulnerable App</h1>
            <div class="navbar-tabs flex flex-wrap justify-center gap-4">
                <a href="/getting-started" class="nav-tab">Getting Started</a>
                <a href="/" class="nav-tab">Login</a>
                <a href="/dashboard" class="nav-tab">Dashboard</a>
                <a href="/comment" class="nav-tab">Comments</a>
                <a href="/transfer" class="nav-tab">Transfer</a>
                <a href="/upload" class="nav-tab">Upload</a>
                <a href="/profile/1" class="nav-tab">Profile</a>
                <a href="/ssrf" class="nav-tab">SSRF</a>
                <a href="/xxe" class="nav-tab">XXE</a>
                <a href="/deserialize" class="nav-tab">Deserialize</a>
                <a href="/reflected-xss" class="nav-tab">Reflected XSS</a>
                <a href="/broken-auth" class="nav-tab bg-blue-600 text-white underline">Broken Auth</a>
                <a href="/blind-sqli" class="nav-tab">Blind SQLi</a>
                <a href="/dom-xss" class="nav-tab">DOM-based XSS</a>
                <a href="/report" class="nav-tab">Report</a>
                <a href="/progress" class="nav-tab">Progress</a>
                <a href="/logout" class="nav-tab">Logout</a>
            </div>
        </div>
    </nav>
    <div class="container mx-auto flex-grow">
        <div class="card">
            <h1 class="text-3xl font-semibold mb-2 text-gray-200 dark:text-gray-200">Broken Authentication</h1>
            <p class="text-gray-400 dark:text-gray-400 mb-2">Broken Authentication Vulnerability: Allows session hijacking or credential stuffing.</p>
            <p class="text-gray-400 dark:text-gray-400 mb-2"><strong>Difficulty:</strong> Medium</p>
            <p class="text-gray-400 dark:text-gray-400 mb-2"><strong>Severity:</strong> Critical</p>
            <p class="text-gray-400 dark:text-gray-400 mb-2"><strong>Real-World Impact:</strong> Can lead to account takeover (e.g., Twitter breach, 2020).</p>
            <p class="text-gray-400 dark:text-gray-400 mb-2"><strong>Reference:</strong> <a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures" class="text-blue-400 dark:text-blue-400 hover:underline">OWASP Top 10: Identification and Authentication Failures</a></p>
            <p class="text-gray-400 dark:text-gray-400 mb-4"><strong>Mitigation:</strong> Use secure session management and strong password policies.</p>
            <div class="mb-4">
                <h2 class="text-xl font-semibold mb-2 text-gray-200 dark:text-gray-200">Theory: Broken Authentication</h2>
                <p class="text-gray-400 dark:text-gray-400">Broken authentication occurs when session management is flawed, allowing attackers to steal session tokens or bypass authentication mechanisms.</p>
            </div>
            {% if success %}
                <div id="success-banner" class="bg-green-900 dark:bg-green-900 border-l-4 border-green-500 dark:border-green-500 text-green-300 dark:text-green-300 p-4 mb-4 flex items-center">
                    <span class="mr-2">🎉</span>
                    <p>{{ success }}</p>
                </div>
            {% endif %}
            {% if error %}
                <p class="text-red-400 dark:text-red-400 font-medium mb-4">{{ error }}</p>
            {% endif %}
            <form method="POST" action="" class="space-y-6 max-w-md">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <div class="form-group">
                    <input type="text" name="session_token" placeholder=" " class="w-full border rounded px-3 py-2 bg-gray-700 dark:bg-gray-700 text-gray-200 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500" value="{{ request.form.session_token or '' }}">
                    <label class="text-gray-400 dark:text-gray-400">Session ID</label>
                </div>
                <button type="submit" class="w-full bg-blue-600 text-white rounded px-4 py-2 hover:bg-blue-700 transition-colors">Authenticate</button>
            </form>
            {% if result %}
                <div class="mt-4">
                    <h2 class="text-2xl font-semibold mb-2 text-gray-200 dark:text-gray-200">Authentication Result</h2>
                    <pre class="bg-gray-800 dark:bg-gray-800 p-4 rounded text-gray-200 dark:text-gray-200">{{ result }}</pre>
                </div>
            {% endif %}
            <div class="mt-4">
                <h2 class="text-xl font-semibold mb-2 text-gray-200 dark:text-gray-200">Solution Walkthrough</h2>
                <button id="open-hint" class="px-4 py-2 bg-yellow-600 text-white rounded hover:bg-yellow-700 transition-colors mr-2">Hint</button>
                <button id="open-solution" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">View Solution</button>
                <div id="hint-modal" class="fixed inset-0 flex items-center justify-center hidden z-50">
                    <div class="modal-content bg-gray-800 dark:bg-gray-800 p-6 rounded-lg shadow-lg max-w-md w-full max-h-[80vh] overflow-y-auto transform transition-all duration-300">
                        <h3 class="text-lg font-semibold mb-2 text-gray-200 dark:text-gray-200">Hint: Broken Authentication</h3>
                        <p class="text-gray-400 dark:text-gray-400 mb-4">Try using a session ID like <code class="text-yellow-400 dark:text-yellow-400">admin-session-123</code> to see if you can authenticate as another user.</p>
                        <button id="close-hint" class="px-4 py-2 bg-orange-600 text-white rounded hover:bg-orange-700 transition-colors">Close</button>
                    </div>
                </div>
                <div id="solution-modal" class="fixed inset-0 flex items-center justify-center hidden z-50">
                    <div class="modal-content bg-gray-800 dark:bg-gray-800 p-6 rounded-lg shadow-lg max-w-md w-full max-h-[80vh] overflow-y-auto transform transition-all duration-300">
                        <h3 class="text-lg font-semibold mb-2 text-gray-200 dark:text-gray-200">Solution Walkthrough: Broken Authentication</h3>
                        <div class="text-gray-400 dark:text-gray-400 mb-4">
                            <p>1. Obtain a session ID (e.g., <code class="text-yellow-400 dark:text-yellow-400">admin-session-123</code>).</p>
                            <p>2. Enter the session ID in the form.</p>
                            <p>3. Submit to gain unauthorized access.</p>
                        </div>
                        <button id="close-solution" class="px-4 py-2 bg-orange-600 text-white rounded hover:bg-orange-700 transition-colors">Close</button>
                    </div>
                </div>
            </div>
            <div class="mt-4">
                <h2 class="text-xl font-semibold mb-2 text-gray-200 dark:text-gray-200">Defensive Coding: Secure Version</h2>
                <p class="text-gray-400 dark:text-gray-400 mb-2">Implement secure session management:</p>
                <pre class="bg-gray-800 dark:bg-gray-800 p-4 rounded text-gray-200 dark:text-gray-200">
from flask import session
from datetime import timedelta
session['user_id'] = user.id
session.permanent = True
app.permanent_session_lifetime = timedelta(minutes=30)
                </pre>
                <p class="text-gray-400 dark:text-gray-400">This ensures sessions are secure and expire appropriately.</p>
            </div>
            {% if ctf_flag and success %}
                <div class="mt-4">
                    <h2 class="text-xl font-semibold mb-2 text-gray-200 dark:text-gray-200">CTF Flag</h2>
                    <p class="text-green-400 dark:text-green-400">{{ ctf_flag }}</p>
                </div>
            {% endif %}
            <div class="mt-4">
                <a href="/reset/broken-auth" class="inline-block px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition-colors">Reset Challenge</a>
            </div>
        </div>
    </div>
    <footer class="bg-gray-800 dark:bg-gray-800 text-white dark:text-white text-center py-4 mt-auto">
        <p class="text-center">© 2025 Vulnerable Web App. All rights reserved.</p>
        <button id="theme-toggle" class="mt-2 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">Toggle Light/Dark Mode</button>
    </footer>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const body = document.body;
            const htmlElement = document.documentElement;
            const successBanner = document.getElementById('success-banner');
            const openHintBtn = document.getElementById('open-hint');
            const hintModal = document.getElementById('hint-modal');
            const closeHintBtn = document.getElementById('close-hint');
            const openSolutionBtn = document.getElementById('open-solution');
            const solutionModal = document.getElementById('solution-modal');
            const solutionContent = solutionModal ? solutionModal.querySelector('.modal-content') : null;
            const closeSolutionBtn = document.getElementById('close-solution');
            const themeToggle = document.getElementById('theme-toggle');

            // Function to apply dark mode styles to the solution modal
            const applyModalDarkModeStyles = () => {
                if (solutionModal && solutionContent) {
                    solutionContent.classList.remove('bg-white');
                    solutionContent.classList.add('bg-gray-800');
                    const textElements = solutionContent.querySelectorAll('p, h3');
                    textElements.forEach(el => {
                        if (el.tagName === 'H3') {
                            el.classList.remove('text-gray-800');
                            el.classList.add('text-gray-200');
                        } else {
                            el.classList.remove('text-gray-600');
                            el.classList.add('text-gray-400');
                        }
                    });
                }
            };

            // Function to apply light mode styles to the solution modal
            const applyModalLightModeStyles = () => {
                if (solutionModal && solutionContent) {
                    solutionContent.classList.remove('bg-gray-800');
                    solutionContent.classList.add('bg-white');
                    const textElements = solutionContent.querySelectorAll('p, h3');
                    textElements.forEach(el => {
                        if (el.tagName === 'H3') {
                            el.classList.remove('text-gray-200');
                            el.classList.add('text-gray-800');
                        } else {
                            el.classList.remove('text-gray-400');
                            el.classList.add('text-gray-600');
                        }
                    });
                }
            };

            // Check for saved theme preference, default to dark if none exists
            const currentTheme = localStorage.getItem('theme') || 'dark';
            if (currentTheme === 'light') {
                htmlElement.classList.remove('dark');
                htmlElement.classList.add('light');
                body.classList.remove('dark');
                body.classList.add('light');
                applyModalLightModeStyles();
            } else {
                htmlElement.classList.remove('light');
                htmlElement.classList.add('dark');
                body.classList.remove('light');
                body.classList.add('dark');
                applyModalDarkModeStyles();
            }

            // Ensure modals are hidden on load
            if (hintModal) {
                hintModal.classList.add('hidden');
            }
            if (solutionModal) {
                solutionModal.classList.add('hidden');
            }

            if (successBanner) {
                setTimeout(() => {
                    successBanner.classList.add('hidden');
                }, 5000);
            }

            if (openHintBtn && hintModal && closeHintBtn) {
                openHintBtn.addEventListener('click', () => {
                    hintModal.classList.remove('hidden');
                    hintModal.classList.add('z-50');
                    body.classList.add('modal-open');
                });
                closeHintBtn.addEventListener('click', () => {
                    hintModal.classList.add('hidden');
                    body.classList.remove('modal-open');
                });
            }

            if (openSolutionBtn && solutionModal && closeSolutionBtn) {
                openSolutionBtn.addEventListener('click', () => {
                    solutionModal.classList.remove('hidden');
                    solutionModal.classList.add('z-50');
                    body.classList.add('modal-open');
                });
                closeSolutionBtn.addEventListener('click', () => {
                    solutionModal.classList.add('hidden');
                    body.classList.remove('modal-open');
                });
                document.addEventListener('keydown', (e) => {
                    if (e.key === 'Escape' && !solutionModal.classList.contains('hidden')) {
                        solutionModal.classList.add('hidden');
                        body.classList.remove('modal-open');
                    }
                });
            }

            themeToggle.addEventListener('click', () => {
                if (htmlElement.classList.contains('dark')) {
                    htmlElement.classList.remove('dark');
                    htmlElement.classList.add('light');
                    body.classList.remove('dark');
                    body.classList.add('light');
                    localStorage.setItem('theme', 'light');
                    applyModalLightModeStyles();
                } else {
                    htmlElement.classList.remove('light');
                    htmlElement.classList.add('dark');
                    body.classList.remove('light');
                    body.classList.add('dark');
                    localStorage.setItem('theme', 'dark');
                    applyModalDarkModeStyles();
                }
            });
        });
    </script>
</body>
</html>