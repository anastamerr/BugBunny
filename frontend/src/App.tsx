import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";

import { Layout } from "./components/layout/Layout";
import Bugs from "./pages/Bugs";
import Chat from "./pages/Chat";
import Correlations from "./pages/Correlations";
import Dashboard from "./pages/Dashboard";
import Incidents from "./pages/Incidents";
import Predictions from "./pages/Predictions";
import Settings from "./pages/Settings";

const queryClient = new QueryClient();

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="incidents" element={<Incidents />} />
            <Route path="bugs" element={<Bugs />} />
            <Route path="correlations" element={<Correlations />} />
            <Route path="predictions" element={<Predictions />} />
            <Route path="chat" element={<Chat />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
