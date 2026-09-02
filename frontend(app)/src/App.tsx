import { Suspense, lazy } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "./state/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import AdminRoute from "./components/AdminRoute";
import ServerSettingsRoute from "./components/ServerSettingsRoute";
import AppShell from "./components/AppShell";
import MobileUpdateBanner from "./components/MobileUpdateBanner";
import DesktopAutoUpdater from "./components/DesktopAutoUpdater";
import "./App.css";

// CORRECTIF PERF (retour utilisateur, 2026-09-02) : ces 14 pages étaient auparavant TOUTES
// importées directement en tête de fichier — chargées et compilées d'un coup au tout premier
// démarrage de l'app, même les écrans qu'une session donnée ne visite jamais (Admin, réinitialisation
// de mot de passe, coffre d'urgence...). `lazy()` + `<Suspense>` (voir plus bas) : chaque page n'est
// chargée qu'au moment où on y navigue réellement — démarrage plus rapide, empreinte mémoire
// initiale plus faible. Risque minime pour une app DESKTOP : les fichiers viennent du disque local
// via Tauri (pas d'aller-retour réseau), le court flash de <RouteLoading> ci-dessous est à peine
// perceptible en pratique.
const Register = lazy(() => import("./pages/Register"));
const VerifyEmail = lazy(() => import("./pages/VerifyEmail"));
const Login = lazy(() => import("./pages/Login"));
const Verify2fa = lazy(() => import("./pages/Verify2fa"));
const ForgotPassword = lazy(() => import("./pages/ForgotPassword"));
const ResetPassword = lazy(() => import("./pages/ResetPassword"));
const Vault = lazy(() => import("./pages/Vault"));
const Settings = lazy(() => import("./pages/Settings"));
const EmergencyVaultPage = lazy(() => import("./pages/EmergencyVaultPage"));
const SharedEntryPage = lazy(() => import("./pages/SharedEntryPage"));
const SharedReceivedPage = lazy(() => import("./pages/SharedReceivedPage"));
const SharedVaultsPage = lazy(() => import("./pages/SharedVaultsPage"));
const SharedVaultDetailPage = lazy(() => import("./pages/SharedVaultDetailPage"));
const Admin = lazy(() => import("./pages/Admin"));
const ServerSettings = lazy(() => import("./pages/ServerSettings"));

/** Repli affiché le temps (généralement quelques dizaines de ms, fichiers locaux) que le code
 * d'une page pas encore visitée charge — voir le correctif ci-dessus. */
function RouteLoading() {
  return <div className="flex min-h-screen items-center justify-center bg-neutral-50 dark:bg-neutral-950" />;
}

function App() {
  const { isAuthenticated } = useAuth();

  return (
    <>
      <MobileUpdateBanner />
      <DesktopAutoUpdater />
      <Suspense fallback={<RouteLoading />}>
      <Routes>
      <Route path="/" element={<Navigate to={isAuthenticated ? "/vault" : "/login"} replace />} />
      <Route path="/register" element={<Register />} />
      <Route path="/verify-email" element={<VerifyEmail />} />
      <Route path="/login" element={<Login />} />
      <Route path="/verify-2fa" element={<Verify2fa />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route
        path="/server"
        element={
          <ServerSettingsRoute>
            <ServerSettings />
          </ServerSettingsRoute>
        }
      />
      {/* Route de mise en page (voir components/AppShell.tsx) : englobe TOUTES les pages
       * authentifiées ci-dessous d'une navigation commune (Coffre, Réglages, Administration...) au
       * lieu de chaque page ayant son propre en-tête dupliqué. Chaque route enfant garde SA PROPRE
       * garde (ProtectedRoute/AdminRoute) — AppShell lui-même n'en impose aucune, il se contente
       * d'afficher la nav ; c'est bien la garde de la route enfant qui redirige vers /login si
       * besoin, exactement comme avant. */}
      <Route element={<AppShell />}>
        <Route
          path="/vault"
          element={
            <ProtectedRoute>
              <Vault />
            </ProtectedRoute>
          }
        />
        <Route
          path="/settings"
          element={
            <ProtectedRoute>
              <Settings />
            </ProtectedRoute>
          }
        />
        <Route
          path="/emergency/:id"
          element={
            <ProtectedRoute>
              <EmergencyVaultPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/shared/:id"
          element={
            <ProtectedRoute>
              <SharedEntryPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/shared-with-me"
          element={
            <ProtectedRoute>
              <SharedReceivedPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/shared-vaults"
          element={
            <ProtectedRoute>
              <SharedVaultsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/shared-vaults/:id"
          element={
            <ProtectedRoute>
              <SharedVaultDetailPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin"
          element={
            <AdminRoute>
              <Admin />
            </AdminRoute>
          }
        />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      </Suspense>
    </>
  );
}

export default App;
