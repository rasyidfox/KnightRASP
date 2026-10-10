package io.knightrasp.core

import io.knightrasp.config.Thresholds
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.model.Level
import org.junit.Assert.assertEquals
import org.junit.Test

class ScorerTest {

    private val scorer = Scorer(Thresholds())

    private fun outcome(category: Category, vararg confidences: Float) = CheckOutcome(
        checkId = "test.${category.name.lowercase()}",
        category = category,
        evidence = confidences.map { Evidence(ruleId = "test", confidence = it) },
    )

    @Test
    fun no_evidence_is_none() {
        val result = scorer.assess(emptyList(), nowMs = 1L)
        assertEquals(Level.NONE, result.level)
        assertEquals(0f, result.score, 0.0001f)
    }

    @Test
    fun single_strong_evidence_maps_to_high() {
        val result = scorer.assess(listOf(outcome(Category.ROOT, 0.7f)), nowMs = 1L)
        assertEquals(0.7f, result.score, 0.0001f)
        assertEquals(Level.HIGH, result.level)
    }

    @Test
    fun two_medium_evidence_in_same_category_use_noisy_or() {
        val result = scorer.assess(listOf(outcome(Category.ROOT, 0.5f, 0.5f)), nowMs = 1L)
        assertEquals(0.75f, result.score, 0.0001f)
        assertEquals(0.75f, result.categories.getValue(Category.ROOT), 0.0001f)
    }

    @Test
    fun two_categories_get_small_bonus() {
        val result = scorer.assess(
            listOf(outcome(Category.ROOT, 0.4f), outcome(Category.DEBUG, 0.4f)),
            nowMs = 1L,
        )
        assertEquals(0.4f + Scorer.MULTI_CATEGORY_BONUS, result.score, 0.0001f)
        assertEquals(Level.MEDIUM, result.level)
    }

    @Test
    fun single_category_has_no_bonus() {
        val result = scorer.assess(listOf(outcome(Category.ROOT, 0.4f)), nowMs = 1L)
        assertEquals(0.4f, result.score, 0.0001f)
    }

    @Test
    fun confidence_is_clamped_and_score_capped() {
        val result = scorer.assess(listOf(outcome(Category.ROOT, 1.5f)), nowMs = 1L)
        assertEquals(1f, result.score, 0.0001f)
        assertEquals(Level.CRITICAL, result.level)
    }

    @Test
    fun evidence_is_preserved_in_assessment() {
        val result = scorer.assess(
            listOf(outcome(Category.EMULATOR, 0.5f, 0.6f)),
            nowMs = 42L,
        )
        assertEquals(2, result.evidence.size)
        assertEquals(42L, result.timestampMs)
    }
}
