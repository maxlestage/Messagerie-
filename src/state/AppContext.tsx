//
//  AppContext.tsx
//  Messagerie 🥦
//
//  État global : la clé partagée (Trousseau via expo-secure-store) et les
//  conversations (persistées en JSON via AsyncStorage). Le clair des parties
//  secrètes n'est jamais écrit : seuls les jetons chiffrés le sont.
//

import React, {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as SecureStore from 'expo-secure-store';
import * as Crypto from 'expo-crypto';

import { Conversation, Message } from '../models/types';
import {
  encryptMarked,
  generateKeyBase64,
  keyBytesFromBase64,
} from '../crypto/brocolisCrypto';

const KEY_STORE_NAME = 'shared_aes_key';
const CONVERSATIONS_KEY = 'conversations';

interface AppContextValue {
  loaded: boolean;
  keyBase64: string | null;
  keyBytes: Uint8Array | null;
  hasKey: boolean;
  conversations: Conversation[];

  generateKey: () => Promise<void>;
  importKey: (candidate: string) => Promise<void>;
  clearKey: () => Promise<void>;

  newConversation: (title: string) => Conversation;
  sendMessage: (conversationId: string, rawInput: string) => void;
  receiveMessage: (conversationId: string, wireText: string) => void;
  deleteConversation: (conversationId: string) => void;
  clearMessages: (conversationId: string) => void;
  getConversation: (conversationId: string) => Conversation | undefined;
}

const AppContext = createContext<AppContextValue | null>(null);

function welcomeConversation(): Conversation {
  const now = Date.now();
  return {
    id: Crypto.randomUUID(),
    title: 'Brocolis 🥦',
    messages: [
      {
        id: Crypto.randomUUID(),
        wireText:
          'Bienvenue ! Ici, tout ce que tu mets entre ((doubles parenthèses)) est chiffré avant d’être stocké.',
        sender: 'them',
        date: now - 120000,
      },
      {
        id: Crypto.randomUUID(),
        wireText:
          'Seuls les appareils qui partagent ta clé peuvent lire le clair. Pour les autres, ça reste un jeton [[BROCOLIS:v1:...]].',
        sender: 'them',
        date: now - 60000,
      },
    ],
  };
}

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [loaded, setLoaded] = useState(false);
  const [keyBase64, setKeyBase64] = useState<string | null>(null);
  const [conversations, setConversations] = useState<Conversation[]>([]);

  // Chargement initial.
  useEffect(() => {
    (async () => {
      try {
        const storedKey = await SecureStore.getItemAsync(KEY_STORE_NAME);
        setKeyBase64(storedKey ?? null);
      } catch {
        setKeyBase64(null);
      }

      let convs: Conversation[] = [];
      try {
        const raw = await AsyncStorage.getItem(CONVERSATIONS_KEY);
        if (raw) convs = JSON.parse(raw) as Conversation[];
      } catch {
        convs = [];
      }
      if (convs.length === 0) convs = [welcomeConversation()];

      setConversations(convs);
      setLoaded(true);
    })();
  }, []);

  // Persistance des conversations (après chargement seulement).
  const didLoad = useRef(false);
  useEffect(() => {
    if (!loaded) return;
    if (!didLoad.current) {
      didLoad.current = true;
    }
    AsyncStorage.setItem(CONVERSATIONS_KEY, JSON.stringify(conversations)).catch(
      () => undefined,
    );
  }, [conversations, loaded]);

  const keyBytes = useMemo<Uint8Array | null>(() => {
    if (!keyBase64) return null;
    try {
      return keyBytesFromBase64(keyBase64);
    } catch {
      return null;
    }
  }, [keyBase64]);

  // --- Clé ---

  const generateKey = async () => {
    const b64 = generateKeyBase64();
    await SecureStore.setItemAsync(KEY_STORE_NAME, b64);
    setKeyBase64(b64);
  };

  const importKey = async (candidate: string) => {
    const trimmed = candidate.trim();
    keyBytesFromBase64(trimmed); // valide format/longueur (lève si invalide)
    await SecureStore.setItemAsync(KEY_STORE_NAME, trimmed);
    setKeyBase64(trimmed);
  };

  const clearKey = async () => {
    await SecureStore.deleteItemAsync(KEY_STORE_NAME);
    setKeyBase64(null);
  };

  // --- Conversations ---

  const appendMessage = (conversationId: string, message: Message) => {
    setConversations((prev) =>
      prev.map((c) =>
        c.id === conversationId
          ? { ...c, messages: [...c.messages, message] }
          : c,
      ),
    );
  };

  const newConversation = (title: string): Conversation => {
    const name = title.trim();
    const conv: Conversation = {
      id: Crypto.randomUUID(),
      title: name.length === 0 ? 'Sans titre' : name,
      messages: [],
    };
    setConversations((prev) => [...prev, conv]);
    return conv;
  };

  const sendMessage = (conversationId: string, rawInput: string) => {
    const trimmed = rawInput.trim();
    if (trimmed.length === 0) return;
    const wire = keyBytes ? encryptMarked(trimmed, keyBytes).text : trimmed;
    appendMessage(conversationId, {
      id: Crypto.randomUUID(),
      wireText: wire,
      sender: 'me',
      date: Date.now(),
    });
  };

  const receiveMessage = (conversationId: string, wireText: string) => {
    const trimmed = wireText.trim();
    if (trimmed.length === 0) return;
    appendMessage(conversationId, {
      id: Crypto.randomUUID(),
      wireText: trimmed,
      sender: 'them',
      date: Date.now(),
    });
  };

  const deleteConversation = (conversationId: string) => {
    setConversations((prev) => prev.filter((c) => c.id !== conversationId));
  };

  const clearMessages = (conversationId: string) => {
    setConversations((prev) =>
      prev.map((c) =>
        c.id === conversationId ? { ...c, messages: [] } : c,
      ),
    );
  };

  const getConversation = (conversationId: string) =>
    conversations.find((c) => c.id === conversationId);

  const value: AppContextValue = {
    loaded,
    keyBase64,
    keyBytes,
    hasKey: keyBase64 !== null,
    conversations,
    generateKey,
    importKey,
    clearKey,
    newConversation,
    sendMessage,
    receiveMessage,
    deleteConversation,
    clearMessages,
    getConversation,
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp(): AppContextValue {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp doit être utilisé dans <AppProvider>.');
  return ctx;
}
