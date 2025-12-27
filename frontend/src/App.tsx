import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";

import { RequireAuth } from "./components/auth/RequireAuth";
import { Layout } from "./components/layout/Layout";
import Bugs from "./pages/Bugs";
import BugDetail from "./pages/BugDetail";
import Chat from "./pages/Chat";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import Profile from "./pages/Profile";
import Register from "./pages/Register";
import Repositories from "./pages/Repositories";
import ScanDetail from "./pages/ScanDetail";
import Scans from "./pages/Scans";
import Settings from "./pages/Settings";

const queryClient = new QueryClient();

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route
            path="/"
            element={
              <RequireAuth>
                <Layout />
              </RequireAuth>
            }
          >
            <Route index element={<Dashboard />} />
            <Route path="scans" element={<Scans />} />
            <Route path="scans/:id" element={<ScanDetail />} />
            <Route path="repos" element={<Repositories />} />
            <Route path="profile" element={<Profile />} />
            <Route path="bugs" element={<Bugs />} />
            <Route path="bugs/:id" element={<BugDetail />} />
            <Route path="chat" element={<Chat />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
