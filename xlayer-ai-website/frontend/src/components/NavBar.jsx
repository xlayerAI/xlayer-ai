const { NavLink } = ReactRouterDOM;

function NavBar() {
    return (
        <header className="sticky top-0 z-50 bg-brand-dark/80 backdrop-blur-sm border-b border-gray-800">
            <nav className="container mx-auto px-6 py-4 flex justify-between items-center">
                <NavLink to="/" className="text-2xl font-bold text-white">
                    XLayer<span className="text-brand-blue">AI</span>
                </NavLink>
                <div className="hidden md:flex items-center space-x-8">
                    <NavLink to="/" className="hover:text-brand-blue transition-colors">Home</NavLink>
                    <NavLink to="/tools" className="hover:text-brand-blue transition-colors">Tools</NavLink>
                    <NavLink to="/about" className="hover:text-brand-blue transition-colors">About</NavLink>
                    <NavLink to="/blog" className="hover:text-brand-blue transition-colors">Blog</NavLink>
                    <NavLink to="/contact" className="hover:text-brand-blue transition-colors">Contact</NavLink>
                </div>
                <div>
                    <NavLink to="/vision" className="bg-brand-blue text-white font-semibold px-4 py-2 rounded-lg hover:bg-blue-600 transition-colors">
                        About Our Vision
                    </NavLink>
                </div>
            </nav>
        </header>
    );
}