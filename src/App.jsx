
import { useEffect } from 'react';
import { useAuth } from './components/AuthContext';
import axios from 'axios';
import Login from './components/Login';
import Protected from './components/Protected';
import './App.css';

let hasFetched = false;

function App() {
  const { user, setUser } = useAuth();

  async function fetchProfile() {
    if (hasFetched) return;
    hasFetched = true;

   try {
  const response = await axios.get('/api/profile', {
    withCredentials: true
  });

      if (response.data && response.data.email) {
        setUser(response.data);
      } else {
        setUser(null);
      }
    } catch (error) {
      console.error('There has been an Error', error);
      setUser(null);
    }
  }

  useEffect(() => {
    fetchProfile();
  }, [setUser]);

  return (
    <div className="app-container">
      <div className="app-content">
        {user ? <Protected /> : <Login />}
      </div>

      <footer className="site-footer">
        <p>Developed by Muhammad Raima, Nsajja Comfort Shalom</p>
        <p>S25D14/021, S25D14/017</p>
        <p>© 2026 All rights reserved.</p>
      </footer>
    </div>
  );
}

export default App;
