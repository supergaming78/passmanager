package com.julie.passmanager

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    // CORRECTIF SÉCURITÉ : sans FLAG_SECURE, Android inclut le contenu de cette fenêtre (mots de
    // passe révélés à l'écran) dans la vignette de l'écran "Applications récentes" et autorise
    // n'importe quelle app tierce avec la permission adéquate à capturer/enregistrer l'écran —
    // posé AVANT super.onCreate() (qui affiche la WebView) pour être actif dès le tout premier
    // rendu. Pratique standard pour toute app bancaire/gestionnaire de mots de passe sur Android.
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }
}
