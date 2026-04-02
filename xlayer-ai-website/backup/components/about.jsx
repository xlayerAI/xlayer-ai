function About() {
    return (
        <div className="container mx-auto px-6 py-16">
            <div className="text-center">
                <h1 className="text-4xl md:text-5xl font-extrabold text-white">About XLayer AI</h1>
                <p className="mt-4 max-w-3xl mx-auto text-lg text-gray-400">Pioneering the Future of Cybersecurity Intelligence</p>
            </div>

            <div className="mt-16 grid md:grid-cols-2 gap-16 items-center">
                <div>
                    <h2 className="text-3xl font-bold text-white">Our Mission</h2>
                    <p className="mt-4 text-gray-400">
                        XLayer AI, founded by Sandesh Poudel, is dedicated to democratizing cybersecurity through innovative AI-powered tools. We believe that advanced threat detection and vulnerability analysis should be accessible to organizations of all sizes, not just enterprise giants.
                    </p>
                    <h3 className="text-2xl font-bold text-white mt-8">The XLayer Intelligence Core (XIC)</h3>
                    <p className="mt-4 text-gray-400">
                        At the heart of our platform lies the XLayer Intelligence Core (XIC), our proprietary AI engine that powers all our cybersecurity tools. XIC continuously learns from global threat patterns, providing real-time intelligence and predictive analysis.
                    </p>
                </div>
                <div className="bg-brand-gray p-8 rounded-lg border border-gray-800">
                    <h3 className="text-2xl font-bold text-white mb-4">Core Values</h3>
                    <ul className="space-y-4">
                        <li className="flex items-start">
                            <span className="text-brand-blue text-2xl mr-3">◈</span>
                            <div>
                                <h4 className="font-semibold text-white">Security First</h4>
                                <p className="text-gray-400 text-sm">Built with enterprise-grade security standards and ethical principles.</p>
                            </div>
                        </li>
                         <li className="flex items-start">
                            <span className="text-brand-blue text-2xl mr-3">◈</span>
                            <div>
                                <h4 className="font-semibold text-white">Innovation</h4>
                                <p className="text-gray-400 text-sm">Leveraging cutting-edge AI to stay ahead of emerging threats.</p>
                            </div>
                        </li>
                         <li className="flex items-start">
                            <span className="text-brand-blue text-2xl mr-3">◈</span>
                            <div>
                                <h4 className="font-semibold text-white">Accessibility</h4>
                                <p className="text-gray-400 text-sm">Making advanced cybersecurity tools accessible to all.</p>
                            </div>
                        </li>
                    </ul>
                </div>
            </div>
             <div className="mt-16 text-center">
                <h2 className="text-3xl font-bold text-white">Our Team</h2>
                <p className="mt-2 text-gray-400">We are a passionate team of security researchers, AI engineers, and ethical hackers.</p>
                {/* Placeholder for team members */}
                <div className="mt-8 flex justify-center gap-8">
                     <div className="text-center">
                        <div className="w-24 h-24 bg-gray-700 rounded-full mx-auto mb-2 border-2 border-brand-blue"></div>
                        <p className="font-bold text-white">Sandesh Poudel</p>
                        <p className="text-sm text-brand-blue">Founder & CEO</p>
                    </div>
                </div>
            </div>
        </div>
    );
}