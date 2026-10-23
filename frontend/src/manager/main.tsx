import React from 'react';
import ReactDOM from 'react-dom/client';
import { ManagerApp } from './ManagerApp';
import { createManagerApi } from './api';
import './styles.css';

const root = document.getElementById('root');
if (!root) throw new Error('Manager root missing');
ReactDOM.createRoot(root).render(<React.StrictMode><ManagerApp api={createManagerApi()} /></React.StrictMode>);
