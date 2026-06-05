//
//  KeyScreen.tsx
//  Messagerie 🥦
//
//  Réglages de la clé symétrique partagée : générer, importer, partager,
//  supprimer. Équivalent de `brocolis keygen`.
//

import React, { useState } from 'react';
import {
  Alert,
  ScrollView,
  Share,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import * as Clipboard from 'expo-clipboard';

import { useApp } from '../state/AppContext';

export default function KeyScreen() {
  const { keyBase64, hasKey, generateKey, importKey, clearKey } = useApp();
  const [importText, setImportText] = useState('');

  const onGenerate = () => {
    Alert.alert(
      'Générer une nouvelle clé',
      'Les messages chiffrés avec une ancienne clé deviendront illisibles. Continuer ?',
      [
        { text: 'Annuler', style: 'cancel' },
        { text: 'Générer', onPress: () => void generateKey() },
      ],
    );
  };

  const onImport = async () => {
    try {
      await importKey(importText);
      setImportText('');
      Alert.alert('Clé importée', 'Tu peux maintenant lire les messages chiffrés.');
    } catch (e) {
      Alert.alert('Clé invalide', e instanceof Error ? e.message : String(e));
    }
  };

  const onCopy = async () => {
    if (keyBase64) {
      await Clipboard.setStringAsync(keyBase64);
      Alert.alert('Copié', 'La clé est dans le presse-papiers.');
    }
  };

  const onShare = () => {
    if (keyBase64) {
      Share.share({ message: keyBase64 }).catch(() => undefined);
    }
  };

  const onClear = () => {
    Alert.alert(
      'Supprimer la clé',
      'Sans clé, les messages chiffrés deviennent illisibles. Cette action est irréversible.',
      [
        { text: 'Annuler', style: 'cancel' },
        { text: 'Supprimer', style: 'destructive', onPress: () => void clearKey() },
      ],
    );
  };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <Text style={styles.sectionTitle}>Clé partagée actuelle</Text>
      {hasKey ? (
        <View style={styles.card}>
          <Text style={styles.keyText} selectable>
            {keyBase64}
          </Text>
          <View style={styles.actionsRow}>
            <TouchableOpacity style={styles.smallButton} onPress={onCopy}>
              <Text style={styles.smallButtonText}>Copier</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.smallButton} onPress={onShare}>
              <Text style={styles.smallButtonText}>Partager</Text>
            </TouchableOpacity>
          </View>
          <Text style={styles.footer}>
            Transmets cette clé par un canal sûr aux personnes avec qui tu veux
            échanger. Quiconque possède la clé peut lire les messages chiffrés.
          </Text>
        </View>
      ) : (
        <View style={styles.card}>
          <Text style={styles.warning}>🔓 Aucune clé configurée</Text>
        </View>
      )}

      <Text style={styles.sectionTitle}>Générer</Text>
      <TouchableOpacity style={styles.button} onPress={onGenerate}>
        <Text style={styles.buttonText}>🔑 Générer une nouvelle clé</Text>
      </TouchableOpacity>
      <Text style={styles.footer}>
        Crée une clé AES-256 aléatoire (équivalent de `brocolis keygen`).
      </Text>

      <Text style={styles.sectionTitle}>Importer</Text>
      <TextInput
        style={styles.input}
        placeholder="Clé base64 (32 octets)"
        value={importText}
        onChangeText={setImportText}
        autoCapitalize="none"
        autoCorrect={false}
        multiline
      />
      <TouchableOpacity
        style={[styles.button, importText.trim() === '' && styles.buttonDisabled]}
        onPress={onImport}
        disabled={importText.trim() === ''}
      >
        <Text style={styles.buttonText}>Importer cette clé</Text>
      </TouchableOpacity>
      <Text style={styles.footer}>
        Colle la clé reçue d’un correspondant (ou générée par brocolis) pour
        pouvoir lire ses messages.
      </Text>

      {hasKey ? (
        <>
          <Text style={styles.sectionTitle}>Zone sensible</Text>
          <TouchableOpacity style={styles.dangerButton} onPress={onClear}>
            <Text style={styles.dangerButtonText}>🗑 Supprimer la clé</Text>
          </TouchableOpacity>
        </>
      ) : null}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f2f2f7' },
  content: { padding: 16, paddingBottom: 40 },
  sectionTitle: {
    fontSize: 13,
    fontWeight: '600',
    color: '#666',
    textTransform: 'uppercase',
    marginTop: 22,
    marginBottom: 8,
  },
  card: {
    backgroundColor: '#fff',
    borderRadius: 12,
    padding: 14,
  },
  keyText: { fontFamily: 'Courier', fontSize: 13, color: '#111' },
  warning: { color: '#a4660a', fontSize: 15 },
  actionsRow: { flexDirection: 'row', marginTop: 12, gap: 10 },
  smallButton: {
    backgroundColor: '#eaf4ea',
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 8,
  },
  smallButtonText: { color: '#2e7d2e', fontWeight: '600' },
  button: {
    backgroundColor: '#4a9e4a',
    paddingVertical: 13,
    borderRadius: 10,
    alignItems: 'center',
  },
  buttonDisabled: { backgroundColor: '#bcd9bc' },
  buttonText: { color: '#fff', fontSize: 16, fontWeight: '600' },
  input: {
    backgroundColor: '#fff',
    borderRadius: 10,
    padding: 12,
    fontFamily: 'Courier',
    fontSize: 13,
    minHeight: 60,
    marginBottom: 10,
    textAlignVertical: 'top',
  },
  dangerButton: {
    backgroundColor: '#fde8e8',
    paddingVertical: 13,
    borderRadius: 10,
    alignItems: 'center',
  },
  dangerButtonText: { color: '#c62828', fontSize: 16, fontWeight: '600' },
  footer: { fontSize: 12, color: '#888', marginTop: 8 },
});
