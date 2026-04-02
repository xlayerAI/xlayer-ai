function Chatbot() {
    const [isOpen, setIsOpen] = React.useState(false);
    const [messages, setMessages] = React.useState([
        { text: "Hello! I'm XIC, your AI cybersecurity assistant. How can I help you today?", sender: 'bot' }
    ]);
    const [input, setInput] = React.useState('');
    const [isLoading, setIsLoading] = React.useState(false);
    const chatEndRef = React.useRef(null);

    React.useEffect(() => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    const handleSendMessage = async () => {
        if (!input.trim()) return;

        const userMessage = { text: input, sender: 'user' };
        setMessages(prev => [...prev, userMessage]);
        setInput('');
        setIsLoading(true);

        try {
            // IMPORTANT: Replace this URL with your deployed Render API URL
            const response = await fetch('https://xlayer-ai-backend.onrender.com/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: input }),
            });

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            const data = await response.json();
            const botMessage = { text: data.response, sender: 'bot' };
            setMessages(prev => [...prev, botMessage]);

        } catch (error) {
            const errorMessage = { text: "Error: Unable to connect to XIC. Please try again later.", sender: 'bot' };
            setMessages(prev => [...prev, errorMessage]);
        } finally {
            setIsLoading(false);
        }
    };

    if (!isOpen) {
        return (
            <button
                onClick={() => setIsOpen(true)}
                className="fixed bottom-5 right-5 bg-brand-blue text-white w-16 h-16 rounded-full flex items-center justify-center shadow-lg hover:bg-blue-600 transition-transform transform hover:scale-110"
            >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M18 10c0 3.866-3.582 7-8 7a8.839 8.839 0 01-4.082-.973l-1.15.383a.5.5 0 01-.6-.6l.384-1.15A8.838 8.838 0 012 10c0-3.866 3.582-7 8-7s8 3.134 8 7zM4.415 13.585a6.836 6.836 0 002.502 1.436.5.5 0 01.32.51l-.23 1.838 1.838-.23a.5.5 0 01.51.32A6.836 6.836 0 0010 18c3.313 0 6-2.686 6-6s-2.687-6-6-6-6 2.686-6 6c0 1.25.378 2.408 1.035 3.415l.17.255-.17.255z" clipRule="evenodd" /><path d="M6.5 9a.5.5 0 000 1h7a.5.5 0 000-1h-7z" /></svg>
            </button>
        );
    }

    return (
        <div className="fixed bottom-5 right-5 w-full max-w-sm h-[600px] flex flex-col bg-brand-gray border border-gray-700 rounded-xl shadow-2xl">
            <div className="flex justify-between items-center p-4 border-b border-gray-700">
                <h3 className="font-bold text-white">Chat with XIC</h3>
                <button onClick={() => setIsOpen(false)} className="text-gray-400 hover:text-white">&times;</button>
            </div>
            <div className="flex-1 p-4 overflow-y-auto">
                <div className="flex flex-col space-y-2">
                    {messages.map((msg, idx) => (
                        <div key={idx} className={`chat-bubble ${msg.sender === 'user' ? 'bg-brand-blue text-white self-end' : 'bg-gray-700 text-gray-200 self-start'}`}>
                            {msg.text}
                        </div>
                    ))}
                    {isLoading && <div className="chat-bubble bg-gray-700 text-gray-200 self-start">Connecting to XIC...</div>}
                    <div ref={chatEndRef} />
                </div>
            </div>
            <div className="p-4 border-t border-gray-700 flex items-center">
                <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                    className="flex-grow bg-gray-800 text-white p-2 rounded-l-md focus:outline-none focus:ring-2 focus:ring-brand-blue"
                    placeholder="Ask XIC..."
                />
                <button onClick={handleSendMessage} className="bg-brand-blue p-2 rounded-r-md hover:bg-blue-600 disabled:bg-gray-500" disabled={isLoading}>
                    Send
                </button>
            </div>
        </div>
    );
}