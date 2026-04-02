const { HashRouter, Routes, Route } = ReactRouterDOM;

function App() {
    return (
        <HashRouter>
            <div className="relative">
                <NavBar />
                <main>
                    <Routes>
                        <Route path="/" element={<Home />} />
                        <Route path="/about" element={<About />} />
                        <Route path="/tools" element={<Tools />} />
                        <Route path="/blog" element={<Blog />} />
                        <Route path="/contact" element={<Contact />} />
                        <Route path="/vision" element={<Vision />} />
                    </Routes>
                </main>
                <Footer />
                <Chatbot />
            </div>
        </HashRouter>
    );
}

ReactDOM.render(<App />, document.getElementById('root'));