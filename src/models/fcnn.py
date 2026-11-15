"""
Fully Connected Neural Network (FCNN / Multi-Layer Perceptron) for Event Profiles.

Input: 8 basepoint cosine similarities (bp_01 to bp_08), each in [0.0, 1.0].
Output: Threat probability in [0.0, 1.0] (Sigmoid activation).
"""

try:
    import keras
    from keras import layers, models, regularizers
    HAS_KERAS = True
except ImportError:
    try:
        from tensorflow import keras
        from tensorflow.keras import layers, models, regularizers
        HAS_KERAS = True
    except ImportError:
        keras = None
        layers = None
        models = None
        regularizers = None
        HAS_KERAS = False


def build_fcnn(input_dim: int = 8, learning_rate: float = 0.001):
    """
    Builds and compiles a regularized FCNN model for binary threat detection.

    Architecture:
      Input (8) -> Dense(64, ReLU) -> BatchNorm -> Dropout(0.3)
                -> Dense(32, ReLU) -> BatchNorm -> Dropout(0.2)
                -> Dense(16, ReLU)
                -> Dense(1, Sigmoid)
    """
    if not HAS_KERAS:
        raise ImportError("TensorFlow / Keras is not installed or available.")

    inputs = layers.Input(shape=(input_dim,), name="profile_input")
    x = layers.Dense(64, activation="relu", kernel_regularizer=regularizers.l2(1e-4), name="dense_1")(inputs)
    x = layers.BatchNormalization(name="batch_norm_1")(x)
    x = layers.Dropout(0.3, name="dropout_1")(x)

    x = layers.Dense(32, activation="relu", kernel_regularizer=regularizers.l2(1e-4), name="dense_2")(x)
    x = layers.BatchNormalization(name="batch_norm_2")(x)
    x = layers.Dropout(0.2, name="dropout_2")(x)

    x = layers.Dense(16, activation="relu", name="dense_3")(x)
    outputs = layers.Dense(1, activation="sigmoid", name="threat_probability")(x)

    model = models.Model(inputs=inputs, outputs=outputs, name="FCNN_EventProfile")
    optimizer = keras.optimizers.Adam(learning_rate=learning_rate)
    model.compile(
        optimizer=optimizer,
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            keras.metrics.Precision(name="precision"),
            keras.metrics.Recall(name="recall"),
            keras.metrics.AUC(name="pr_auc", curve="PR")
        ]
    )
    return model
