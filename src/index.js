import React from 'react';
import ReactDOM from 'react-dom/client';
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import './index.scss';
import reportWebVitals from './reportWebVitals';

import logo from './logo.svg';
import icon from "./Images/icon-w.png";

import Success from "./Pages/Success";

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <div className="splash-bg">
      <div className="bg-image"></div>
      <div className="form text-center">
        <img className="logo" src={icon} alt="MFKDF" />
        <div className="card text-start">
          <Router>
            <Routes>
              <Route path="/success" element={<Success />} />
            </Routes>
          </Router>
        </div>
      </div>
    </div>
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
