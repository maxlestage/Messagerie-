//
//  ConversationsScreen.tsx
//  Messagerie 🥦
//

import React, { useLayoutEffect } from 'react';
import {
  Alert,
  FlatList,
  Pressable,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from 'react-native';
import { NativeStackScreenProps } from '@react-navigation/native-stack';

import { useApp } from '../state/AppContext';
import {
  Conversation,
  RootStackParamList,
  lastMessageDate,
} from '../models/types';
import { containsToken, decryptTokens } from '../crypto/brocolisCrypto';

type Props = NativeStackScreenProps<RootStackParamList, 'Conversations'>;

function previewText(
  conversation: Conversation,
  keyBytes: Uint8Array | null,
): string {
  const last = conversation.messages[conversation.messages.length - 1];
  if (!last) return 'Aucun message';
  if (!keyBytes) {
    return containsToken(last.wireText) ? '🔒 Message chiffré' : last.wireText;
  }
  return decryptTokens(last.wireText, keyBytes).text;
}

function formatTime(epochMs: number): string {
  if (epochMs === 0) return '';
  const d = new Date(epochMs);
  return `${d.getHours().toString().padStart(2, '0')}:${d
    .getMinutes()
    .toString()
    .padStart(2, '0')}`;
}

export default function ConversationsScreen({ navigation }: Props) {
  const { conversations, keyBytes, hasKey, newConversation, deleteConversation } =
    useApp();

  const sorted = [...conversations].sort(
    (a, b) => lastMessageDate(b) - lastMessageDate(a),
  );

  const promptNewConversation = () => {
    Alert.prompt(
      'Nouvelle conversation',
      'Donne un nom à ta conversation.',
      (name) => {
        if (name !== undefined) {
          const conv = newConversation(name ?? '');
          navigation.navigate('Chat', { conversationId: conv.id });
        }
      },
    );
  };

  useLayoutEffect(() => {
    navigation.setOptions({
      headerLeft: () => (
        <Pressable
          onPress={() => navigation.navigate('Key')}
          hitSlop={12}
          accessibilityLabel="Clé de chiffrement"
        >
          <Text style={styles.headerIcon}>{hasKey ? '🔑' : '🔓'}</Text>
        </Pressable>
      ),
      headerRight: () => (
        <Pressable
          onPress={promptNewConversation}
          hitSlop={12}
          accessibilityLabel="Nouvelle conversation"
        >
          <Text style={styles.headerIcon}>✏️</Text>
        </Pressable>
      ),
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navigation, hasKey]);

  const confirmDelete = (conversation: Conversation) => {
    Alert.alert(
      'Supprimer la conversation',
      `Supprimer « ${conversation.title} » ?`,
      [
        { text: 'Annuler', style: 'cancel' },
        {
          text: 'Supprimer',
          style: 'destructive',
          onPress: () => deleteConversation(conversation.id),
        },
      ],
    );
  };

  return (
    <View style={styles.container}>
      {!hasKey ? (
        <TouchableOpacity
          style={styles.banner}
          onPress={() => navigation.navigate('Key')}
        >
          <Text style={styles.bannerTitle}>🔓 Aucune clé de chiffrement</Text>
          <Text style={styles.bannerSubtitle}>
            Touche ici pour en générer une ou en importer une.
          </Text>
        </TouchableOpacity>
      ) : null}

      <FlatList
        data={sorted}
        keyExtractor={(item) => item.id}
        ListEmptyComponent={
          <Text style={styles.empty}>
            Aucune conversation. Touche ✏️ pour en créer une.
          </Text>
        }
        renderItem={({ item }) => (
          <TouchableOpacity
            style={styles.rowItem}
            onPress={() =>
              navigation.navigate('Chat', { conversationId: item.id })
            }
            onLongPress={() => confirmDelete(item)}
          >
            <View style={styles.rowHeader}>
              <Text style={styles.title} numberOfLines={1}>
                {item.title}
              </Text>
              <Text style={styles.time}>
                {formatTime(lastMessageDate(item))}
              </Text>
            </View>
            <Text style={styles.preview} numberOfLines={1}>
              {previewText(item, keyBytes)}
            </Text>
          </TouchableOpacity>
        )}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#ffffff' },
  headerIcon: { fontSize: 20 },
  banner: {
    backgroundColor: '#fff4e5',
    padding: 14,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: '#f0d9b5',
  },
  bannerTitle: { fontSize: 16, fontWeight: '600', color: '#a4660a' },
  bannerSubtitle: { fontSize: 13, color: '#a4660a', marginTop: 2 },
  rowItem: {
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: '#e0e0e0',
  },
  rowHeader: { flexDirection: 'row', justifyContent: 'space-between' },
  title: { fontSize: 17, fontWeight: '600', flexShrink: 1, color: '#111' },
  time: { fontSize: 12, color: '#999', marginLeft: 8 },
  preview: { fontSize: 14, color: '#666', marginTop: 2 },
  empty: { textAlign: 'center', color: '#999', marginTop: 40 },
});
