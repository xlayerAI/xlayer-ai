import React from 'react';
import './index.css'; // या './style.css' if that's your CSS

import NavBar from './components/NavBar';
import Home from './components/Home';
import Tools from './components/Tools';
import Vision from './components/Vision';
import BLOG from './components/BLOG';
import Contact from './components/Contact';
import Footer from './components/Footer';
import Chatbot from './components/Chatbot';

function App() {
  return (
    <div className="App">
      <NavBar />
      <Home />
      <Tools />
      <Vision />
      <BLOG />
      <Contact />
      <Footer />
      <Chatbot />
    </div>
  );
}

export default App;