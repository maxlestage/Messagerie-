//
//  ChatScreen.tsx
//  Messagerie 🥦
//

import React, { useLayoutEffect, useRef, useState } from 'react';
import {
  Alert,
  FlatList,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import { NativeStackScreenProps } from '@react-navigation/native-stack';

import { useApp } from '../state/AppContext';
import { Message, RootStackParamList } from '../models/types';
import MessageBubble from '../components/MessageBubble';

type Props = NativeStackScreenProps<RootStackParamList, 'Chat'>;

export default function ChatScreen({ route, navigation }: Props) {
  const { conversationId } = route.params;
  const {
    getConversation,
    keyBytes,
    hasKey,
    sendMessage,
    receiveMessage,
    clearMessages,
  } = useApp();

  const conversation = getConversation(conversationId);
  const [draft, setDraft] = useState('');
  const [showRaw, setShowRaw] = useState(false);
  const listRef = useRef<FlatList<Message>>(null);

  const promptReceive = () => {
    Alert.prompt(
      'Recevoir un message',
      'Colle un message reçu d’un correspondant (chiffré ou non). Il sera déchiffré avec ta clé.',
      (value) => {
        if (value) receiveMessage(conversationId, value);
      },
    );
  };

  const confirmClear = () => {
    Alert.alert('Effacer la conversation', 'Supprimer tous les messages ?', [
      { text: 'Annuler', style: 'cancel' },
      {
        text: 'Effacer',
        style: 'destructive',
        onPress: () => clearMessages(conversationId),
      },
    ]);
  };

  const openMenu = () => {
    Alert.alert(conversation?.title ?? 'Conversation', undefined, [
      {
        text: showRaw ? 'Voir le texte déchiffré' : 'Voir le texte chiffré',
        onPress: () => setShowRaw((v) => !v),
      },
      { text: 'Recevoir un message', onPress: promptReceive },
      { text: 'Effacer la conversation', style: 'destructive', onPress: confirmClear },
      { text: 'Annuler', style: 'cancel' },
    ]);
  };

  useLayoutEffect(() => {
    navigation.setOptions({
      title: conversation?.title ?? 'Conversation',
      headerRight: () => (
        <Pressable onPress={openMenu} hitSlop={12} accessibilityLabel="Options">
          <Text style={styles.headerIcon}>⋯</Text>
        </Pressable>
      ),
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navigation, conversation?.title, showRaw]);

  if (!conversation) {
    return (
      <View style={styles.centered}>
        <Text style={styles.missing}>Conversation introuvable.</Text>
      </View>
    );
  }

  const handleSend = () => {
    sendMessage(conversationId, draft);
    setDraft('');
  };

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      keyboardVerticalOffset={Platform.OS === 'ios' ? 90 : 0}
    >
      <FlatList
        ref={listRef}
        data={conversation.messages}
        keyExtractor={(item) => item.id}
        contentContainerStyle={styles.listContent}
        renderItem={({ item }) => (
          <MessageBubble message={item} keyBytes={keyBytes} showRaw={showRaw} />
        )}
        onContentSizeChange={() =>
          listRef.current?.scrollToEnd({ animated: true })
        }
        ListEmptyComponent={
          <Text style={styles.empty}>Aucun message. Écris le premier !</Text>
        }
      />

      <View style={styles.composer}>
        <Text style={styles.hint}>
          {hasKey
            ? 'Astuce : mets un secret entre ((doubles parenthèses)) pour le chiffrer.'
            : '⚠️ Aucune clé : les secrets ne seront pas chiffrés.'}
        </Text>
        <View style={styles.inputRow}>
          <TextInput
            style={styles.input}
            placeholder="Message…"
            value={draft}
            onChangeText={setDraft}
            multiline
          />
          <TouchableOpacity
            style={[styles.sendButton, draft.trim() === '' && styles.sendDisabled]}
            onPress={handleSend}
            disabled={draft.trim() === ''}
          >
            <Text style={styles.sendIcon}>↑</Text>
          </TouchableOpacity>
        </View>
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#ffffff' },
  headerIcon: { fontSize: 24, color: '#ffffff', paddingHorizontal: 4 },
  centered: { flex: 1, alignItems: 'center', justifyContent: 'center' },
  missing: { color: '#999' },
  listContent: { paddingHorizontal: 12, paddingVertical: 10, flexGrow: 1 },
  empty: { textAlign: 'center', color: '#999', marginTop: 40 },
  composer: {
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: '#d9d9d9',
    paddingHorizontal: 10,
    paddingTop: 6,
    paddingBottom: 10,
    backgroundColor: '#fafafa',
  },
  hint: { fontSize: 11, color: '#888', marginBottom: 6 },
  inputRow: { flexDirection: 'row', alignItems: 'flex-end' },
  input: {
    flex: 1,
    minHeight: 38,
    maxHeight: 120,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: '#bbb',
    borderRadius: 18,
    paddingHorizontal: 14,
    paddingTop: 8,
    paddingBottom: 8,
    fontSize: 16,
    backgroundColor: '#fff',
  },
  sendButton: {
    width: 38,
    height: 38,
    borderRadius: 19,
    backgroundColor: '#4a9e4a',
    alignItems: 'center',
    justifyContent: 'center',
    marginLeft: 8,
  },
  sendDisabled: { backgroundColor: '#bcd9bc' },
  sendIcon: { color: '#fff', fontSize: 20, fontWeight: '700' },
});
