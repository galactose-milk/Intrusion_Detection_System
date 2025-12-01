// frontend/src/App.jsx
import React, { useState } from 'react';
import './App.css'; // Import specific styles for the App layout
import SidePanel from './components/SidePanel';
import MainScreen from './components/MainScreen';

function App() {
  // State to track the currently selected view
  const [currentView, setCurrentView] = useState('setup'); // Default view

  return (
    <div className="App">
      <SidePanel onViewChange={setCurrentView} currentView={currentView} />
      <MainScreen activeView={currentView} />
    </div>
  );
}

export default App;