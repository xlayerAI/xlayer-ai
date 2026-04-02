function Home() {
    // Placeholder data - you can expand on this
    const tools = [
        { name: "PhishShield", desc: "Real-time phishing detection and email security analysis.", icon: "🛡️" },
        { name: "ReconBot", desc: "Automated network reconnaissance and vulnerability mapping.", icon: "🤖" },
        { name: "LeakHunter", desc: "Advanced data breach detection and monitoring system.", icon: "💧" },
        { name: "XBot", desc: "AI-powered cybersecurity assistant and threat analysis.", icon: "💬" },
        { name: "CVE-Explain", desc: "Comprehensive vulnerability analysis and patch management.", icon: "🔬" },
    ];
    
    return (
        <div className="space-y-24 md:space-y-32 my-12">
            {/* Hero Section */}
            <section className="container mx-auto px-6 text-center">
                <h1 className="text-4xl md:text-6xl font-extrabold text-white leading-tight">
                    Empowering Cybersecurity with <br /> <span className="text-brand-blue">AI-Driven Intelligence</span>
                </h1>
                <p className="mt-4 max-w-2xl mx-auto text-lg text-gray-400">
                    Making advanced cybersecurity accessible through innovative AI-powered tools for ethical hacking, threat detection, and vulnerability analysis.
                </p>
                <div className="mt-8 flex justify-center gap-4">
                    <a href="#tools" className="bg-brand-blue text-white font-semibold px-6 py-3 rounded-lg hover:bg-blue-600 transition-colors">
                        Explore Tools
                    </a>
                    <button className="border border-gray-700 text-white font-semibold px-6 py-3 rounded-lg hover:bg-gray-800 transition-colors">
                        Watch Demo
                    </button>
                </div>
            </section>

            {/* Stats Section */}
            <section className="container mx-auto px-6 grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
                <div>
                    <p className="text-4xl font-bold text-brand-blue">10M+</p>
                    <p className="text-gray-400">Threat Detections</p>
                </div>
                <div>
                    <p className="text-4xl font-bold text-brand-purple">5M+</p>
                    <p className="text-gray-400">Security Scans</p>
                </div>
                <div>
                    <p className="text-4xl font-bold text-brand-blue">50K+</p>
                    <p className="text-gray-400">CVE Analyses</p>
                </div>
                <div>
                    <p className="text-4xl font-bold text-brand-purple">25K+</p>
                    <p className="text-gray-400">Active Users</p>
                </div>
            </section>

            {/* Tools Showcase Section */}
            <section id="tools" className="container mx-auto px-6">
                <div className="text-center mb-12">
                    <h2 className="text-3xl md:text-4xl font-bold text-white">AI-Powered Security Tools</h2>
                    <p className="max-w-xl mx-auto mt-2 text-gray-400">Our comprehensive suite of AI-driven tools designed to protect, detect, and analyze cybersecurity threats.</p>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                    {tools.map(tool => (
                        <div key={tool.name} className="bg-brand-gray border border-gray-800 p-6 rounded-lg hover:border-brand-blue transition-all duration-300 transform hover:-translate-y-1">
                            <div className="text-4xl mb-4">{tool.icon}</div>
                            <h3 className="text-xl font-bold text-white">{tool.name}</h3>
                            <p className="text-gray-400 mt-2">{tool.desc}</p>
                            <a href="#/tools" className="text-brand-blue font-semibold mt-4 inline-block hover:underline">Learn More →</a>
                        </div>
                    ))}
                </div>
            </section>
             {/* Testimonials */}
            <section className="container mx-auto px-6 text-center">
                 <h2 className="text-3xl md:text-4xl font-bold text-white mb-8">What Our Users Say</h2>
                 <div className="max-w-3xl mx-auto">
                    <div className="bg-brand-gray p-8 rounded-lg">
                        <p className="text-lg italic text-gray-300">"XLayer AI stopped a sophisticated phishing attack in seconds, saving us from a potential disaster. Their tools are intuitive and incredibly powerful."</p>
                        <p className="mt-4 font-semibold text-white">- CTO, SecureTech Solutions</p>
                    </div>
                 </div>
            </section>
        </div>
    );
}