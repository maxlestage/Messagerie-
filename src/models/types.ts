//
//  types.ts
//  Messagerie 🥦
//

export type Sender = 'me' | 'them';

/**
 * Un message tel qu'il « voyage » : les segments secrets y sont déjà sous
 * forme de jetons chiffrés `[[BROCOLIS:v1:...]]`. Le stockage ne contient
 * donc jamais le clair des parties marquées.
 */
export interface Message {
  id: string;
  /** Texte « sur le fil » (parties secrètes = jetons chiffrés). */
  wireText: string;
  sender: Sender;
  /** Horodatage epoch (ms). */
  date: number;
}

export interface Conversation {
  id: string;
  title: string;
  messages: Message[];
}

/** Date du dernier message (pour trier), 0 si vide. */
export function lastMessageDate(conversation: Conversation): number {
  const last = conversation.messages[conversation.messages.length - 1];
  return last ? last.date : 0;
}

/** Paramètres de navigation. */
export type RootStackParamList = {
  Conversations: undefined;
  Chat: { conversationId: string };
  Key: undefined;
};
